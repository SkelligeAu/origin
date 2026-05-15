// Package v0fixtures is the canonical interoperability fixture for
// Origin Protocol v0 (see protocol/origin-protocol-v0.md §14).
//
// Every test in this file re-derives a fixture artefact from its source
// JSON, using the same canonicalisation / hashing / signing primitives
// the implementation uses, and asserts byte-equality against the stored
// reference. If a test fails, either:
//   - the implementation has drifted from the canonicalisation rules
//     in the spec → fix the implementation or revise the spec;
//   - or the fixture inputs need regeneration → run gen.go.
//
// Any change that flips one of these tests is a deliberate event, never
// a silent one. CI runs this on every PR.
package v0fixtures

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/SkelligeAu/origin/internal/assertion"
	"github.com/SkelligeAu/origin/internal/canon"
)

const (
	testKeySeedString = "origin-protocol-v0-fixture-signing-key"
)

// testKey loads the fixture signing key from disk; falls back to the
// deterministic seed-derived key if the file is missing.
func testKey(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey, string) {
	t.Helper()
	seed := sha256.Sum256([]byte(testKeySeedString))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	pubHash := sha256.Sum256(pub)
	fp := hex.EncodeToString(pubHash[:])[:16]

	// Sanity: the file on disk must match the seed-derived key.
	pubOnDisk, err := os.ReadFile("keys/test-signer.pub")
	if err != nil {
		t.Fatalf("missing keys/test-signer.pub: %v", err)
	}
	if !bytes.Equal(pubOnDisk, pub) {
		t.Fatalf("test signing key on disk does not match the seed-derived key")
	}
	return priv, pub, fp
}

// readFixture loads a path under the fixture dir and returns its bytes.
func readFixture(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(rel)
	if err != nil {
		t.Fatalf("%s: %v", rel, err)
	}
	return b
}

// loadIdentity reads a fixture identity JSON.
func loadIdentity(t *testing.T, prefix string) assertion.Identity {
	t.Helper()
	var i assertion.Identity
	if err := json.Unmarshal(readFixture(t, prefix+".json"), &i); err != nil {
		t.Fatalf("%s: %v", prefix, err)
	}
	return i
}

func loadOccurrence(t *testing.T, prefix string) assertion.Occurrence {
	t.Helper()
	var o assertion.Occurrence
	if err := json.Unmarshal(readFixture(t, prefix+".json"), &o); err != nil {
		t.Fatalf("%s: %v", prefix, err)
	}
	return o
}

// expectedID strips trailing newline from an *.expected-id file.
func expectedID(t *testing.T, rel string) string {
	t.Helper()
	b := readFixture(t, rel)
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return string(b)
}

// TestIdentityFixture: each identity JSON canonicalises and hashes to
// the recorded canonical-bytes and expected-id, byte-for-byte.
func TestIdentityFixture(t *testing.T) {
	cases := []struct {
		name, prefix string
	}{
		{"observation", "identity/observation"},
		{"verified", "identity/verified"},
		{"peer_reports", "identity/peer_reports"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			i := loadIdentity(t, c.prefix)
			cb, err := i.CanonicalBytes()
			if err != nil {
				t.Fatalf("canonical bytes: %v", err)
			}
			want := readFixture(t, c.prefix+".canonical-bytes")
			if !bytes.Equal(cb, want) {
				t.Errorf("canonical bytes drift for %s\nwant: %s\ngot:  %s", c.prefix, want, cb)
			}
			id, err := i.ComputeID()
			if err != nil {
				t.Fatalf("compute id: %v", err)
			}
			if id != expectedID(t, c.prefix+".expected-id") {
				t.Errorf("id drift for %s: got %s, want %s", c.prefix, id, expectedID(t, c.prefix+".expected-id"))
			}
			if id != i.ID {
				t.Errorf("recomputed id %s != stored id %s", id, i.ID)
			}
		})
	}
}

// TestOccurrenceFixture: canonical bytes, IDs, and signatures match the
// recorded fixtures.
func TestOccurrenceFixture(t *testing.T) {
	priv, pub, fp := testKey(t)
	cases := []struct {
		name, prefix string
	}{
		{"observer", "occurrence/observer"},
		{"federated_importer", "occurrence/federated_importer"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			o := loadOccurrence(t, c.prefix)
			cb, err := o.CanonicalBytes()
			if err != nil {
				t.Fatalf("canonical bytes: %v", err)
			}
			want := readFixture(t, c.prefix+".canonical-bytes")
			if !bytes.Equal(cb, want) {
				t.Errorf("canonical bytes drift\nwant: %s\ngot:  %s", want, cb)
			}
			id, err := o.ComputeID()
			if err != nil {
				t.Fatalf("compute id: %v", err)
			}
			if id != expectedID(t, c.prefix+".expected-id") {
				t.Errorf("id drift: got %s, want %s", id, expectedID(t, c.prefix+".expected-id"))
			}
			// Re-sign with the deterministic test key and compare.
			sig, err := o.Sign(priv, fp)
			if err != nil {
				t.Fatalf("sign: %v", err)
			}
			expectedSigRaw := readFixture(t, c.prefix+".expected-signature")
			for len(expectedSigRaw) > 0 && (expectedSigRaw[len(expectedSigRaw)-1] == '\n' || expectedSigRaw[len(expectedSigRaw)-1] == '\r') {
				expectedSigRaw = expectedSigRaw[:len(expectedSigRaw)-1]
			}
			if sig != string(expectedSigRaw) {
				t.Errorf("signature drift\nwant: %s\ngot:  %s", expectedSigRaw, sig)
			}
			// Verify the stored signature too — protocol §4.6.
			if err := o.VerifySignature(func(_ string) (ed25519.PublicKey, error) {
				return pub, nil
			}); err != nil {
				t.Errorf("verify stored signature: %v", err)
			}
		})
	}
}

// TestClaimFixture: canonicalised claim bytes (after §5.3 exclusion) and
// computed ID match the fixture.
func TestClaimFixture(t *testing.T) {
	raw := readFixture(t, "claim/sample.json")
	var claim map[string]any
	if err := json.Unmarshal(raw, &claim); err != nil {
		t.Fatal(err)
	}
	cb, err := canonicalizeClaim(claim)
	if err != nil {
		t.Fatalf("canonicalize claim: %v", err)
	}
	want := readFixture(t, "claim/sample.canonical-bytes")
	if !bytes.Equal(cb, want) {
		t.Errorf("canonical bytes drift\nwant: %s\ngot:  %s", want, cb)
	}
	h := sha256.Sum256(cb)
	id := hex.EncodeToString(h[:])
	if id != expectedID(t, "claim/sample.expected-id") {
		t.Errorf("id drift: got %s want %s", id, expectedID(t, "claim/sample.expected-id"))
	}
	storedID, _ := claim["id"].(string)
	if id != storedID {
		t.Errorf("recomputed id %s != stored id %s", id, storedID)
	}
}

func canonicalizeClaim(claim map[string]any) ([]byte, error) {
	c := map[string]any{}
	for k, v := range claim {
		switch k {
		case "id", "signature", "evaluated_at",
			"projection_manifest_hash", "identities_hash":
			continue
		}
		c[k] = v
	}
	if d, ok := c["derivation"].(map[string]any); ok {
		dc := map[string]any{}
		for k, v := range d {
			if k == "occurrences_cited" {
				continue
			}
			dc[k] = v
		}
		c["derivation"] = dc
	}
	b, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	return canon.CanonicalizeJSON(b)
}

// TestRawEvidenceFixture: payload bytes hash to the recorded hash.
func TestRawEvidenceFixture(t *testing.T) {
	payload := readFixture(t, "raw-evidence/sample-payload.bin")
	got := sha256.Sum256(payload)
	want := expectedID(t, "raw-evidence/sample-payload.expected-hash")
	if hex.EncodeToString(got[:]) != want {
		t.Errorf("payload hash drift: got %x, want %s", got, want)
	}
}

// TestKeyDeterminism asserts the fixture key on disk matches the
// seed-derived key. (Already enforced inside testKey(); this is a named
// test for clarity in CI output.)
func TestKeyDeterminism(t *testing.T) {
	_, _, fp := testKey(t)
	if len(fp) != 16 {
		t.Fatalf("unexpected fingerprint length %d", len(fp))
	}
}

// TestFixtureLayout is a smoke test that every documented fixture file
// exists. New fixtures should be added here as well.
func TestFixtureLayout(t *testing.T) {
	expected := []string{
		"keys/test-signer.pub",
		"keys/test-signer.ed25519",
		"identity/observation.json",
		"identity/observation.canonical-bytes",
		"identity/observation.expected-id",
		"identity/verified.json",
		"identity/verified.canonical-bytes",
		"identity/verified.expected-id",
		"identity/peer_reports.json",
		"identity/peer_reports.canonical-bytes",
		"identity/peer_reports.expected-id",
		"occurrence/observer.json",
		"occurrence/observer.canonical-bytes",
		"occurrence/observer.expected-id",
		"occurrence/observer.expected-signature",
		"occurrence/federated_importer.json",
		"occurrence/federated_importer.canonical-bytes",
		"occurrence/federated_importer.expected-id",
		"occurrence/federated_importer.expected-signature",
		"claim/sample.json",
		"claim/sample.canonical-bytes",
		"claim/sample.expected-id",
		"raw-evidence/sample-payload.bin",
		"raw-evidence/sample-payload.expected-hash",
	}
	for _, rel := range expected {
		if _, err := os.Stat(filepath.Clean(rel)); err != nil {
			t.Errorf("missing fixture file %s: %v", rel, err)
		}
	}
}
