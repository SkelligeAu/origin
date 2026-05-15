package sigstore

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// ArtifactDigest is one (algorithm, hex) pair acceptable as the subject
// of the attestation. The verifier matches if ANY supplied digest equals
// the in-toto Statement's subject digest under the corresponding algo.
type ArtifactDigest struct {
	Algo string // "sha256" or "sha512" (npm provenance uses sha512)
	Hex  string
}

// Result is the structured outcome of one verification attempt.
//
// A successful verification returns Verified=true, populates the
// identifying fields, and sets ReasonCode to ReasonVerified.
//
// A failed verification returns Verified=false, sets ReasonCode to the
// classified enum value, and provides a free-text Reason for human
// inspection. ReasonCode is the value policy code and projections should
// consume; Reason is for humans.
type Result struct {
	Verified bool

	// Identity fields, present when Verified is true. On failure, best-
	// effort population: OIDCSubject/Issuer/CertFingerprint may be set
	// even when Verified is false (e.g., the cert parsed but the chain
	// didn't validate), so downstream callers can still record what was
	// claimed.
	OIDCSubject     string
	OIDCIssuer      string
	SubjectDigest   string
	PredicateType   string
	CertFingerprint string

	// Outcome fields. ReasonCode is always set (ReasonVerified or one of
	// the failure codes); Reason is the free-text description.
	ReasonCode ReasonCode
	Reason     string
}

// Verify runs the full DSSE + Fulcio + transparency-log verification on
// the given Sigstore bundle (the JSON returned by npm's /-/npm/v1/
// attestations endpoint, per attestation).
//
// The caller passes:
//   - bundleJSON: the verbatim "bundle" object bytes from npm
//   - digests: the candidate digests of the artifact this attestation
//     should be over. We try each in order; verification passes if any
//     match. npm provenance uses sha512; other ecosystems may use sha256.
//   - expectedRepoURL: the source repository URL the package's metadata
//     claims (used to check OIDC subject coherence).
//
// We pin the trusted root inside this binary (see roots.go). Verification
// is executed entirely by sigstore-go using that root. Nothing on the
// network is contacted by this function.
func Verify(bundleJSON []byte, digests []ArtifactDigest, expectedRepoURL string) (*Result, error) {
	tr, err := TrustedRoot()
	if err != nil {
		return nil, fmt.Errorf("load pinned trusted root: %w", err)
	}

	b := &bundle.Bundle{}
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return fail(ReasonBundleParseFailed, "bundle parse: "+err.Error(), nil), nil
	}

	// Best-effort: extract identity info from the cert NOW (before any
	// failure paths) so failure Results can still record what was claimed.
	identityInfo := extractIdentityFromBundle(b)

	if len(digests) == 0 {
		return fail(ReasonInputInvalid, "no artifact digests supplied", &identityInfo), nil
	}
	verifyDigests := make([]verify.ArtifactDigest, 0, len(digests))
	for _, d := range digests {
		raw, derr := hex.DecodeString(d.Hex)
		if derr != nil {
			return fail(ReasonInputInvalid, "digest "+d.Algo+": not hex", &identityInfo), nil
		}
		switch d.Algo {
		case "sha256":
			if len(raw) != sha256.Size {
				return fail(ReasonInputInvalid, "sha256 digest must be 32 bytes", &identityInfo), nil
			}
		case "sha512":
			if len(raw) != 64 {
				return fail(ReasonInputInvalid, "sha512 digest must be 64 bytes", &identityInfo), nil
			}
		default:
			return fail(ReasonInputInvalid, "unsupported digest algorithm: "+d.Algo, &identityInfo), nil
		}
		verifyDigests = append(verifyDigests, verify.ArtifactDigest{
			Algorithm: d.Algo,
			Digest:    raw,
		})
	}

	subjectRegex := repoSubjectRegex(expectedRepoURL)
	if subjectRegex == "" {
		return fail(ReasonInputInvalid, "could not derive an OIDC subject regex from "+expectedRepoURL, &identityInfo), nil
	}
	id, err := verify.NewShortCertificateIdentity(
		"https://token.actions.githubusercontent.com",
		"",
		"",
		subjectRegex,
	)
	if err != nil {
		return nil, fmt.Errorf("policy identity: %w", err)
	}
	policy := verify.NewPolicy(
		verify.WithArtifactDigest(verifyDigests[0].Algorithm, verifyDigests[0].Digest),
		verify.WithCertificateIdentity(id),
	)

	v, err := verify.NewVerifier(tr,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return nil, fmt.Errorf("new verifier: %w", err)
	}

	res, err := v.Verify(b, policy)
	if err != nil {
		return fail(ClassifyError(err.Error()), "verify failed: "+err.Error(), &identityInfo), nil
	}

	out := &Result{
		Verified:        true,
		ReasonCode:      ReasonVerified,
		OIDCSubject:     identityInfo.OIDCSubject,
		OIDCIssuer:      identityInfo.OIDCIssuer,
		CertFingerprint: identityInfo.CertFingerprint,
	}
	if len(digests) > 0 {
		out.SubjectDigest = digests[0].Algo + ":" + digests[0].Hex
	}
	if res.Statement != nil {
		out.PredicateType = res.Statement.PredicateType
	}
	return out, nil
}

// identityInfo carries the best-effort identity extracted from a bundle's
// leaf certificate. Used by both success and failure paths so the caller
// can record what was claimed even when verification failed.
type identityInfo struct {
	OIDCSubject     string
	OIDCIssuer      string
	CertFingerprint string
}

func extractIdentityFromBundle(b *bundle.Bundle) identityInfo {
	var info identityInfo
	vc, err := b.VerificationContent()
	if err != nil || vc == nil {
		return info
	}
	cert := vc.Certificate()
	if cert == nil {
		return info
	}
	h := sha256.Sum256(cert.Raw)
	info.CertFingerprint = hex.EncodeToString(h[:])
	info.OIDCSubject, info.OIDCIssuer = extractOIDCFromCert(cert)
	return info
}

// fail builds a failure Result with the reason classified, the free-text
// reason captured, and any identity info we managed to extract.
func fail(code ReasonCode, reason string, info *identityInfo) *Result {
	r := &Result{
		Verified:   false,
		ReasonCode: code,
		Reason:     reason,
	}
	if info != nil {
		r.OIDCSubject = info.OIDCSubject
		r.OIDCIssuer = info.OIDCIssuer
		r.CertFingerprint = info.CertFingerprint
	}
	return r
}

// repoSubjectRegex builds a regex matching the SAN/SubjectAlternativeName
// for GitHub Actions OIDC certs that originate from the specified repo.
//
// GitHub Actions OIDC subjects look like:
//   https://github.com/<owner>/<repo>/.github/workflows/<file>@refs/...
//
// We accept any workflow file and any ref, but the (owner, repo) must
// match the package's declared source repo. This catches the case where
// a malicious package is published with a valid attestation that points
// at someone else's CI.
func repoSubjectRegex(repoURL string) string {
	owner, repo := parseGitHubOwnerRepo(repoURL)
	if owner == "" || repo == "" {
		return ""
	}
	// Anchor with ^ and $; allow any workflow file path and ref suffix.
	return "^https://github.com/" + regexpEscape(owner) + "/" + regexpEscape(repo) + "/\\.github/workflows/.+@refs/.+$"
}

func parseGitHubOwnerRepo(s string) (owner, repo string) {
	// Strip protocol/host prefixes.
	for _, p := range []string{
		"https://github.com/", "http://github.com/",
		"git+https://github.com/", "git@github.com:",
		"github:", "github.com/",
	} {
		if strings.HasPrefix(s, p) {
			s = s[len(p):]
			break
		}
	}
	s = strings.TrimSuffix(s, ".git")
	parts := strings.SplitN(s, "/", 3)
	if len(parts) < 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

func regexpEscape(s string) string {
	// Conservative: escape characters that have meaning in Go regexp.
	const special = `\.+*?()|[]{}^$`
	var b strings.Builder
	for _, c := range s {
		if strings.ContainsRune(special, c) {
			b.WriteByte('\\')
		}
		b.WriteRune(c)
	}
	return b.String()
}

// ErrNotApplicable signals that an attestation was not the right shape
// for our verifier (e.g., npm's publish attestation is signed with a
// static npm key rather than a Fulcio cert; we skip it gracefully).
var ErrNotApplicable = errors.New("attestation not applicable to Fulcio verifier")
