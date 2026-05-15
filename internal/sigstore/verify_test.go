package sigstore

import (
	_ "embed"
	"strings"
	"testing"
)

//go:embed testdata/bundle_sigstore_sign_2_3_2.json
var fixtureBundleJSON []byte

// Known-good values for the fixture (@sigstore/sign@2.3.2 SLSA Provenance).
// Hardcoded here so tests are hermetic; if the fixture is replaced these
// must be updated together.
const (
	fixtureSHA512 = "e55cf974f56eba7208bc2e6f05bd003f0a3ba8a0381bdc8ce3c90f5894fe384111b38d267791a8511d7279dc297a4599e26d07870e389bacd4f8e6ec38dfa20c"
	fixtureRepo   = "https://github.com/sigstore/sigstore-js"
	fixtureSAN    = "https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main"
)

// TestVerify_HappyPath: valid bundle, correct sha512, correct expected
// repo → Verified=true with populated OIDC fields.
func TestVerify_HappyPath(t *testing.T) {
	r, err := Verify(fixtureBundleJSON, []ArtifactDigest{
		{Algo: "sha512", Hex: fixtureSHA512},
	}, fixtureRepo)
	if err != nil {
		t.Fatalf("verifier internal error: %v", err)
	}
	if !r.Verified {
		t.Fatalf("expected Verified=true, got reason=%s (%s)", r.ReasonCode, r.Reason)
	}
	if r.ReasonCode != ReasonVerified {
		t.Errorf("ReasonCode = %q, want %q", r.ReasonCode, ReasonVerified)
	}
	if r.OIDCSubject != fixtureSAN {
		t.Errorf("OIDCSubject = %q, want %q", r.OIDCSubject, fixtureSAN)
	}
	if r.OIDCIssuer != "https://token.actions.githubusercontent.com" {
		t.Errorf("OIDCIssuer = %q, want GitHub Actions", r.OIDCIssuer)
	}
	if r.CertFingerprint == "" {
		t.Error("CertFingerprint empty on successful verify")
	}
}

// TestVerify_WrongDigest: valid bundle, deliberately wrong sha512 →
// Verified=false, ReasonCode=subject_digest_mismatch.
func TestVerify_WrongDigest(t *testing.T) {
	wrongHex := strings.Repeat("00", 64)
	r, err := Verify(fixtureBundleJSON, []ArtifactDigest{
		{Algo: "sha512", Hex: wrongHex},
	}, fixtureRepo)
	if err != nil {
		t.Fatalf("verifier internal error: %v", err)
	}
	if r.Verified {
		t.Fatal("expected Verified=false for wrong digest")
	}
	if r.ReasonCode != ReasonSubjectDigestMismatch {
		t.Errorf("ReasonCode = %q, want %q (reason text: %q)",
			r.ReasonCode, ReasonSubjectDigestMismatch, r.Reason)
	}
	// Identity should still be extractable even though verification failed.
	if r.OIDCSubject == "" {
		t.Error("expected OIDCSubject populated on best-effort failure path")
	}
}

// TestVerify_WrongRepo: valid bundle, mismatched expected repo →
// Verified=false, ReasonCode=oidc_subject_coherence_failed. This is the
// potentially-malicious case from epistemic-model.v1.md §7.1.
func TestVerify_WrongRepo(t *testing.T) {
	r, err := Verify(fixtureBundleJSON, []ArtifactDigest{
		{Algo: "sha512", Hex: fixtureSHA512},
	}, "https://github.com/fakeorg/fakerepo")
	if err != nil {
		t.Fatalf("verifier internal error: %v", err)
	}
	if r.Verified {
		t.Fatal("expected Verified=false for mismatched repo")
	}
	if r.ReasonCode != ReasonOIDCSubjectCoherenceFailed {
		t.Errorf("ReasonCode = %q, want %q (reason: %q)",
			r.ReasonCode, ReasonOIDCSubjectCoherenceFailed, r.Reason)
	}
}

// TestVerify_MalformedBundle: random non-JSON bytes → Verified=false,
// ReasonCode=bundle_parse_failed. Must not panic.
func TestVerify_MalformedBundle(t *testing.T) {
	garbage := []byte("not a json bundle, not even close, just some bytes")
	r, err := Verify(garbage, []ArtifactDigest{
		{Algo: "sha512", Hex: fixtureSHA512},
	}, fixtureRepo)
	if err != nil {
		t.Fatalf("verifier internal error: %v", err)
	}
	if r.Verified {
		t.Fatal("expected Verified=false for malformed bundle")
	}
	if r.ReasonCode != ReasonBundleParseFailed {
		t.Errorf("ReasonCode = %q, want %q (reason: %q)",
			r.ReasonCode, ReasonBundleParseFailed, r.Reason)
	}
}

// TestVerify_EmptyBundle: empty bytes → bundle_parse_failed.
func TestVerify_EmptyBundle(t *testing.T) {
	r, err := Verify([]byte{}, []ArtifactDigest{
		{Algo: "sha512", Hex: fixtureSHA512},
	}, fixtureRepo)
	if err != nil {
		t.Fatalf("verifier internal error: %v", err)
	}
	if r.Verified {
		t.Fatal("expected Verified=false for empty bundle")
	}
	if r.ReasonCode != ReasonBundleParseFailed {
		t.Errorf("ReasonCode = %q, want %q", r.ReasonCode, ReasonBundleParseFailed)
	}
}

// TestVerify_NoDigests: no digests supplied → input_invalid.
func TestVerify_NoDigests(t *testing.T) {
	r, err := Verify(fixtureBundleJSON, nil, fixtureRepo)
	if err != nil {
		t.Fatalf("verifier internal error: %v", err)
	}
	if r.Verified {
		t.Fatal("expected Verified=false for no digests")
	}
	if r.ReasonCode != ReasonInputInvalid {
		t.Errorf("ReasonCode = %q, want %q", r.ReasonCode, ReasonInputInvalid)
	}
}

// TestVerify_BadHex: digest is not valid hex → input_invalid.
func TestVerify_BadHex(t *testing.T) {
	r, err := Verify(fixtureBundleJSON, []ArtifactDigest{
		{Algo: "sha512", Hex: "zzzzz"},
	}, fixtureRepo)
	if err != nil {
		t.Fatalf("verifier internal error: %v", err)
	}
	if r.Verified {
		t.Fatal("expected Verified=false for bad hex")
	}
	if r.ReasonCode != ReasonInputInvalid {
		t.Errorf("ReasonCode = %q, want %q", r.ReasonCode, ReasonInputInvalid)
	}
}

// TestVerify_UnknownAlgo: unrecognised digest algo → input_invalid.
func TestVerify_UnknownAlgo(t *testing.T) {
	r, err := Verify(fixtureBundleJSON, []ArtifactDigest{
		{Algo: "md5", Hex: strings.Repeat("ab", 16)},
	}, fixtureRepo)
	if err != nil {
		t.Fatalf("verifier internal error: %v", err)
	}
	if r.Verified {
		t.Fatal("expected Verified=false for unknown algo")
	}
	if r.ReasonCode != ReasonInputInvalid {
		t.Errorf("ReasonCode = %q, want %q", r.ReasonCode, ReasonInputInvalid)
	}
}

// TestClassifyError covers the reason mapper in isolation, including the
// degradation-to-Unknown case that protects against silent drift if
// sigstore-go rewords its errors.
func TestClassifyError(t *testing.T) {
	cases := []struct {
		in   string
		want ReasonCode
	}{
		{"provided artifact digests does not match digests in statement", ReasonSubjectDigestMismatch},
		{"no matching CertificateIdentity found", ReasonOIDCSubjectCoherenceFailed},
		{"bundle parse: unexpected end of input", ReasonBundleParseFailed},
		{"failed to verify transparency log inclusion proof", ReasonTransparencyLogProofInvalid},
		{"signature verification failed", ReasonSignatureInvalid},
		{"certificate chain invalid", ReasonCertificateChainInvalid},
		{"sha256 digest must be 32 bytes", ReasonInputInvalid},
		{"completely novel error wording the library may emit", ReasonUnknown},
		{"", ReasonUnknown},
	}
	for _, c := range cases {
		got := ClassifyError(c.in)
		if got != c.want {
			t.Errorf("ClassifyError(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
