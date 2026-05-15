package v0fixtures

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/SkelligeAu/origin/internal/assertion"
	"github.com/SkelligeAu/origin/internal/checkpoint"
)

// TestAnchorFixture re-derives the Phase-5 anchor fixture artefacts and
// asserts byte-equality against the committed reference files.
//
// Specifically verifies (Origin Protocol v0 §3, §6, vocab v6):
//   - The Checkpoint's JCS canonical bytes match the recorded reference.
//   - The Checkpoint's content-addressed IRI matches.
//   - The provider response bytes hash to the recorded hash.
//   - The anchor identity (transparency_log_records_checkpoint) canonicalises
//     and IDs identically.
func TestAnchorFixture(t *testing.T) {
	t.Run("checkpoint", func(t *testing.T) {
		// Re-derive canonical bytes from the pretty JSON copy.
		pretty := readFixture(t, "anchor/checkpoint.json")
		var signed checkpoint.Signed
		if err := json.Unmarshal(pretty, &signed); err != nil {
			t.Fatalf("parse checkpoint.json: %v", err)
		}
		cb, err := signed.SignedCanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		want := readFixture(t, "anchor/checkpoint.canonical-bytes")
		if !bytes.Equal(cb, want) {
			t.Errorf("checkpoint canonical bytes drift\nwant: %s\ngot:  %s", want, cb)
		}
		iri, err := signed.IRI()
		if err != nil {
			t.Fatal(err)
		}
		wantIRI := expectedID(t, "anchor/checkpoint.expected-iri")
		if iri != wantIRI {
			t.Errorf("checkpoint IRI drift: got %s want %s", iri, wantIRI)
		}
	})

	t.Run("provider_response", func(t *testing.T) {
		bytes := readFixture(t, "anchor/provider-response.json")
		got := sha256.Sum256(bytes)
		want := expectedID(t, "anchor/provider-response.expected-hash")
		if hex.EncodeToString(got[:]) != want {
			t.Errorf("provider response hash drift: got %x want %s", got, want)
		}
	})

	t.Run("anchor_identity", func(t *testing.T) {
		raw := readFixture(t, "anchor/anchor-identity.json")
		var i assertion.Identity
		if err := json.Unmarshal(raw, &i); err != nil {
			t.Fatal(err)
		}
		// The anchor identity must be classified observation per vocab v6.
		if i.Predicate != "transparency_log_records_checkpoint" {
			t.Errorf("expected transparency_log_records_checkpoint predicate, got %s", i.Predicate)
		}
		// Re-derive canonical bytes and id.
		cb, err := i.CanonicalBytes()
		if err != nil {
			t.Fatal(err)
		}
		want := readFixture(t, "anchor/anchor-identity.canonical-bytes")
		if !bytes.Equal(cb, want) {
			t.Errorf("anchor identity canonical bytes drift\nwant: %s\ngot:  %s", want, cb)
		}
		id, err := i.ComputeID()
		if err != nil {
			t.Fatal(err)
		}
		wantID := expectedID(t, "anchor/anchor-identity.expected-id")
		if id != wantID {
			t.Errorf("anchor identity ID drift: got %s want %s", id, wantID)
		}
		// Object must be an IRI ref pointing at the provider entry.
		if i.Object.Kind != assertion.ObjectIRI {
			t.Errorf("anchor object kind = %s, want iri", i.Object.Kind)
		}
		if i.Object.IRI != "fakelog:fixture:1" {
			t.Errorf("anchor object IRI = %s, want fakelog:fixture:1", i.Object.IRI)
		}
	})
}

// TestAnchorVocabClass confirms the anchor predicate's verification_class
// is observation in vocab v6 — a structural protection against accidental
// reclassification to verification.
func TestAnchorVocabClass(t *testing.T) {
	raw, err := os.ReadFile("../../vocab/v6.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Predicates map[string]struct {
			VerificationClass string `json:"verification_class"`
		} `json:"predicates"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	checks := map[string]string{
		"transparency_log_records_checkpoint":                  "observation",
		"peer_reports_transparency_log_records_checkpoint_of":  "observation",
	}
	for pred, want := range checks {
		def, ok := doc.Predicates[pred]
		if !ok {
			t.Errorf("vocab v6 missing predicate %q", pred)
			continue
		}
		if def.VerificationClass != want {
			t.Errorf("predicate %s verification_class = %q, want %q (Phase-5 invariant: anchoring is observation, NOT verification)",
				pred, def.VerificationClass, want)
		}
	}
}
