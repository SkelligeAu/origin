package sigstore

import "strings"

// ReasonCode classifies a verification outcome. The set is enumerated; new
// values require a vocabulary-discipline change (rationale + deprecation
// path for any value they subsume). See epistemic-model.v1.md §7.2.
type ReasonCode string

const (
	ReasonVerified                     ReasonCode = "verified"
	ReasonBundleParseFailed            ReasonCode = "bundle_parse_failed"
	ReasonSignatureInvalid             ReasonCode = "signature_invalid"
	ReasonCertificateChainInvalid      ReasonCode = "certificate_chain_invalid"
	ReasonTransparencyLogProofInvalid  ReasonCode = "transparency_log_proof_invalid"
	ReasonSubjectDigestMismatch        ReasonCode = "subject_digest_mismatch"
	ReasonOIDCSubjectCoherenceFailed   ReasonCode = "oidc_subject_coherence_failed"
	ReasonInputInvalid                 ReasonCode = "input_invalid"
	ReasonUnknown                      ReasonCode = "unknown"
)

// ClassifyError maps an error message (from sigstore-go or our own
// pre-flight checks) to one of the enumerated ReasonCode values.
//
// Mapping is heuristic over substrings of the upstream error text. If
// sigstore-go rewords an error in a future release, the mapping degrades
// to ReasonUnknown and the hermetic test suite (verify_test.go) will
// fail loudly so we know to update the mapping deliberately.
func ClassifyError(msg string) ReasonCode {
	if msg == "" {
		return ReasonUnknown
	}
	m := strings.ToLower(msg)
	switch {
	// Pre-flight check failures from our own Verify wrapper.
	case strings.Contains(m, "artifact sha256 must be"),
		strings.Contains(m, "sha256 digest must be"),
		strings.Contains(m, "sha512 digest must be"),
		strings.Contains(m, "digest must be hex"),
		strings.Contains(m, "no artifact digests supplied"),
		strings.Contains(m, "unsupported digest algorithm"),
		strings.Contains(m, "not hex"):
		return ReasonInputInvalid
	case strings.Contains(m, "could not derive an oidc subject regex"):
		return ReasonInputInvalid

	// Bundle structural failures.
	case strings.Contains(m, "bundle parse"),
		strings.Contains(m, "failed to unmarshal"),
		strings.Contains(m, "unmarshal bundle"),
		strings.Contains(m, "invalid bundle"),
		strings.Contains(m, "no envelope"),
		strings.Contains(m, "missing envelope"),
		strings.Contains(m, "missing dsse"),
		strings.Contains(m, "missing verification material"),
		strings.Contains(m, "missing certificate"):
		return ReasonBundleParseFailed

	// Digest mismatch — the artifact we were asked to verify against does
	// not match the in-toto statement's subject digest. sigstore-go phrases
	// this variously: "provided artifact digest(s) does not match digest(s)
	// in statement". The match here MUST run before the generic "signature"
	// case below, because the upstream wraps the error with "failed to
	// verify signature: <real reason>" and the digest-mismatch is the
	// real reason.
	case strings.Contains(m, "provided artifact digest"),
		strings.Contains(m, "artifact digest does not match"),
		strings.Contains(m, "artifact digests does not match"),
		strings.Contains(m, "any digest in statement"),
		strings.Contains(m, "digest mismatch"),
		strings.Contains(m, "subject digest"):
		return ReasonSubjectDigestMismatch

	// OIDC subject / cert identity mismatch. This is the potentially-malicious
	// case: a valid Sigstore attestation but for a different (owner, repo).
	case strings.Contains(m, "no matching certificateidentity"),
		strings.Contains(m, "matching certificate identity"),
		strings.Contains(m, "san"),
		strings.Contains(m, "subject alternative name"),
		strings.Contains(m, "issuer"),
		strings.Contains(m, "oidc"):
		return ReasonOIDCSubjectCoherenceFailed

	// Transparency log proof failures.
	case strings.Contains(m, "transparency log"),
		strings.Contains(m, "tlog"),
		strings.Contains(m, "inclusion proof"),
		strings.Contains(m, "inclusion promise"),
		strings.Contains(m, "rekor"):
		return ReasonTransparencyLogProofInvalid

	// Cryptographic signature failures.
	case strings.Contains(m, "signature"),
		strings.Contains(m, "verifying signature"):
		return ReasonSignatureInvalid

	// Certificate chain / x509 failures.
	case strings.Contains(m, "certificate"),
		strings.Contains(m, "x509"),
		strings.Contains(m, "fulcio"),
		strings.Contains(m, "cert chain"),
		strings.Contains(m, "chain"):
		return ReasonCertificateChainInvalid

	default:
		return ReasonUnknown
	}
}

// String returns the wire form of the code, suitable for JSON storage
// and policy comparison.
func (r ReasonCode) String() string { return string(r) }
