package ingest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/SkelligeAu/origin/internal/assertion"
	"github.com/SkelligeAu/origin/internal/raw"
	"github.com/SkelligeAu/origin/internal/sigstore"
)

// FailureRecord is the JSON payload stored as raw evidence for a
// sigstore.verification_failure record. The payload carries the
// structured reason code, free-text reason, best-effort identity info,
// and a pointer back to the original bundle's content hash so an auditor
// can re-execute the verifier on the exact same inputs.
type FailureRecord struct {
	ReasonCode         sigstore.ReasonCode `json:"reason_code"`
	Reason             string              `json:"reason"`
	OIDCSubject        string              `json:"oidc_subject,omitempty"`
	OIDCIssuer         string              `json:"oidc_issuer,omitempty"`
	CertFingerprint    string              `json:"cert_fingerprint,omitempty"`
	BundleEvidenceID   string              `json:"bundle_evidence_id"`
	ExpectedRepository string              `json:"expected_repository"`
	Verifier           string              `json:"verifier"`
}

// emitVerificationFailure stores a structured failure record and emits a
// cryptographic_verification_failed identity (refutation class). The
// emitter ensures the occurrence carries RoleVerifier (the predicate's
// verification_class is "refutation").
func emitVerificationFailure(
	store *raw.Store, em *emitter,
	priv ed25519.PrivateKey, fp string,
	attestor, now string,
	subjectPURL string,
	bundleBytes []byte,
	attestationsURL, name, version, expectedRepo string,
	result *sigstore.Result,
) error {
	// Persist the bundle so the failure record can cite it by content hash.
	bundleEvidenceID, err := store.Put(raw.Metadata{
		Source:   "sigstore.bundle",
		Endpoint: attestationsURL,
		RequestParams: map[string]string{
			"package":        name,
			"version":        version,
			"predicate_type": "https://slsa.dev/provenance/v1",
		},
		FetchedAt:      now,
		Fetcher:        attestor,
		ResponseStatus: 200,
	}, bundleBytes, priv, fp)
	if err != nil {
		return fmt.Errorf("store bundle for failure record: %w", err)
	}

	// Structured failure payload, persisted as its own raw evidence record.
	failure := FailureRecord{
		ReasonCode:         result.ReasonCode,
		Reason:             result.Reason,
		OIDCSubject:        result.OIDCSubject,
		OIDCIssuer:         result.OIDCIssuer,
		CertFingerprint:    result.CertFingerprint,
		BundleEvidenceID:   bundleEvidenceID,
		ExpectedRepository: expectedRepo,
		Verifier:           "sigstore-attestation-verifier@v0.1.0",
	}
	failureBytes, err := json.MarshalIndent(failure, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal failure record: %w", err)
	}
	failureEvidenceID, err := store.Put(raw.Metadata{
		Source:   "sigstore.verification_failure",
		Endpoint: attestationsURL,
		RequestParams: map[string]string{
			"package":         name,
			"version":         version,
			"reason_code":     string(result.ReasonCode),
			"bundle_evidence": bundleEvidenceID,
		},
		FetchedAt:      now,
		Fetcher:        attestor,
		ResponseStatus: 200,
	}, failureBytes, priv, fp)
	if err != nil {
		return fmt.Errorf("store failure record: %w", err)
	}

	// Object IRI: claimed OIDC identity if extractable, otherwise a
	// synthetic IRI keyed by the unparseable bundle's hash.
	var objectIRI string
	if result.OIDCSubject != "" && result.OIDCIssuer != "" {
		objectIRI = sigstoreIdentityIRI(result.OIDCIssuer, result.OIDCSubject)
	} else {
		h := sha256.Sum256(bundleBytes)
		objectIRI = "sigstore:unparseable_bundle:" + hex.EncodeToString(h[:16])
	}

	id := assertion.Identity{
		Subject:    subjectPURL,
		Predicate:  "cryptographic_verification_failed",
		Object:     assertion.Object{Kind: assertion.ObjectIRI, IRI: objectIRI},
		EvidenceID: failureEvidenceID,
		ObservedAt: now,
		Normalizer: "sigstore-attestation-verifier@v0.1.0",
		Vocab:      VocabVersion,
	}
	if _, _, err := em.emit(id); err != nil {
		return fmt.Errorf("emit failure identity: %w", err)
	}
	return nil
}
