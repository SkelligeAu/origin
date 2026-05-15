package verify

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/SkelligeAu/origin/internal/assertion"
	"github.com/SkelligeAu/origin/internal/raw"
	"github.com/SkelligeAu/origin/internal/sigstore"
)

// checkCryptoReverify re-executes Sigstore verification for every
// cryptographically_verified_signature_by assertion in the log. This is
// the load-bearing test for invariant 16: a verified-form assertion is
// only meaningful if the procedure that produced it can be replayed and
// still passes.
//
// What this check enforces on replay:
//   - The bundle bytes on disk are unchanged (DSSE signature still valid).
//   - The certificate still chains to the pinned Fulcio root.
//   - The transparency-log inclusion proof still verifies.
//   - The OIDC subject in the cert still matches the regex we'd build for
//     the GitHub repository it claims (subject-source coherence is
//     reproduced from the cert itself).
//   - The artifact-digest in the in-toto statement is unchanged.
//
// What this check does NOT enforce on replay:
//   - That the original cross-source check (npm.registry's repository
//     field == OIDC subject's repo) was correct at ingest time. That
//     check ran once when the assertion was first emitted; its passing
//     is what allowed the assertion to exist. Replay verifies the bundle
//     remains valid against its own self-asserted identity.
//
// Failures here are categorized:
//   - tamper: bundle bytes have changed; cryptographic integrity broken.
//   - drift: cert expiration, root rotation, or other time-bound state.
//
// Day-1 simplification: we report both as failures with reason; future
// versions can split the categories formally.
func checkCryptoReverify() (string, error) {
	idents, err := assertion.NewIdentityStore(filepath.Join(dataDir, "assertions", "identities"))
	if err != nil {
		return "", err
	}
	store, err := raw.New(filepath.Join(dataDir, "raw"))
	if err != nil {
		return "", err
	}
	var verified int
	var firstErr error
	err = idents.Walk(func(i assertion.Identity) error {
		if i.Predicate != "cryptographically_verified_signature_by" {
			return nil
		}
		verified++
		// The identity's evidence_id points at the structured sigstore.
		// verification_failure record on the failure path; on the success
		// path it points at the bundle directly. Both shapes resolve through
		// raw store; bundles are recognizable because their bytes ARE the
		// DSSE+verificationMaterial JSON.
		_, evidenceBytes, _, err := store.Get(i.EvidenceID)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("identity %s: load evidence: %w", i.ID, err)
			}
			return nil
		}
		bundleBytes, berr := resolveBundleBytes(evidenceBytes, store)
		if berr != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("identity %s: resolve bundle: %w", i.ID, berr)
			}
			return nil
		}
		digests, derr := digestsFromBundle(bundleBytes)
		if derr != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("identity %s: %w", i.ID, derr)
			}
			return nil
		}
		expectedRepo, rerr := repoFromCert(bundleBytes)
		if rerr != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("identity %s: %w", i.ID, rerr)
			}
			return nil
		}
		res, verr := sigstore.Verify(bundleBytes, digests, expectedRepo)
		if verr != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("identity %s: verifier error: %w", i.ID, verr)
			}
			return nil
		}
		if !res.Verified {
			if firstErr == nil {
				firstErr = fmt.Errorf("identity %s: re-verification failed: %s", i.ID, res.Reason)
			}
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if firstErr != nil {
		return "", firstErr
	}
	if verified == 0 {
		return "no verified-form identities present", nil
	}
	return fmt.Sprintf("%d verified-form identities re-verified", verified), nil
}

// resolveBundleBytes accepts either a Sigstore bundle directly, or a
// FailureRecord JSON pointing to a bundle by evidence id. On the failure
// path the verified-form identity does not exist; this resolver is only
// called for verified-form identities, so it is the bundle case in
// practice. It tolerates the failure-record shape defensively in case
// future identity shapes get encoded indirectly.
func resolveBundleBytes(evidence []byte, store *raw.Store) ([]byte, error) {
	// If it parses as our FailureRecord shape, follow the pointer.
	var maybe struct {
		BundleEvidenceID string `json:"bundle_evidence_id"`
	}
	if err := json.Unmarshal(evidence, &maybe); err == nil && maybe.BundleEvidenceID != "" {
		_, b, _, err := store.Get(maybe.BundleEvidenceID)
		return b, err
	}
	return evidence, nil
}

// digestsFromBundle extracts the in-toto Statement's subject digests
// from a Sigstore bundle's DSSE payload. The payload is base64-encoded
// JSON of an in-toto Statement.
func digestsFromBundle(bundleJSON []byte) ([]sigstore.ArtifactDigest, error) {
	var bundle struct {
		DsseEnvelope struct {
			Payload string `json:"payload"`
		} `json:"dsseEnvelope"`
	}
	if err := json.Unmarshal(bundleJSON, &bundle); err != nil {
		return nil, fmt.Errorf("parse bundle: %w", err)
	}
	if bundle.DsseEnvelope.Payload == "" {
		return nil, fmt.Errorf("bundle has no dsseEnvelope.payload")
	}
	raw, err := base64.StdEncoding.DecodeString(bundle.DsseEnvelope.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	var stmt struct {
		Subject []struct {
			Name   string            `json:"name"`
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
	}
	if err := json.Unmarshal(raw, &stmt); err != nil {
		return nil, fmt.Errorf("parse statement: %w", err)
	}
	if len(stmt.Subject) == 0 {
		return nil, fmt.Errorf("statement has no subjects")
	}
	var out []sigstore.ArtifactDigest
	for algo, hex := range stmt.Subject[0].Digest {
		out = append(out, sigstore.ArtifactDigest{Algo: algo, Hex: hex})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("statement subject has no digests")
	}
	return out, nil
}

// repoFromCert extracts (owner, repo) from the cert's OIDC subject URI
// and reconstructs a GitHub URL the verifier's regex builder accepts.
func repoFromCert(bundleJSON []byte) (string, error) {
	var b struct {
		VerificationMaterial struct {
			Certificate struct {
				RawBytes string `json:"rawBytes"`
			} `json:"certificate"`
			X509CertificateChain struct {
				Certificates []struct {
					RawBytes string `json:"rawBytes"`
				} `json:"certificates"`
			} `json:"x509CertificateChain"`
		} `json:"verificationMaterial"`
	}
	if err := json.Unmarshal(bundleJSON, &b); err != nil {
		return "", fmt.Errorf("parse bundle: %w", err)
	}
	rb := b.VerificationMaterial.Certificate.RawBytes
	if rb == "" && len(b.VerificationMaterial.X509CertificateChain.Certificates) > 0 {
		rb = b.VerificationMaterial.X509CertificateChain.Certificates[0].RawBytes
	}
	if rb == "" {
		return "", fmt.Errorf("bundle has no leaf certificate bytes")
	}
	certDER, err := base64.StdEncoding.DecodeString(rb)
	if err != nil {
		return "", fmt.Errorf("decode cert: %w", err)
	}
	subject, err := sigstore.OIDCSubjectFromDER(certDER)
	if err != nil {
		return "", err
	}
	owner, repo := splitGitHubOwnerRepo(subject)
	if owner == "" || repo == "" {
		return "", fmt.Errorf("could not extract owner/repo from OIDC subject %q", subject)
	}
	return "https://github.com/" + owner + "/" + repo, nil
}

func splitGitHubOwnerRepo(oidcSubject string) (string, string) {
	const prefix = "https://github.com/"
	if !strings.HasPrefix(oidcSubject, prefix) {
		return "", ""
	}
	rest := strings.TrimPrefix(oidcSubject, prefix)
	// Form: <owner>/<repo>/.github/workflows/<file>@refs/...
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) < 2 {
		return "", ""
	}
	return parts[0], parts[1]
}
