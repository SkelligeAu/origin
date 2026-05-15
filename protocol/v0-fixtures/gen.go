//go:build ignore

// gen.go produces protocol/v0-fixtures/. Run once when fixture inputs
// change; the generated artefacts are committed to the repo.
//
//   cd protocol/v0-fixtures && go run gen.go
//
// The fixture self-test (fixtures_test.go) re-derives every artefact and
// asserts byte-equality against the files this program writes.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/SkelligeAu/origin/internal/assertion"
	"github.com/SkelligeAu/origin/internal/canon"
	"github.com/SkelligeAu/origin/internal/checkpoint"
)

const (
	// Deterministic test-key seed. The seed string is documented so
	// anyone can regenerate identical keys. THIS KEY IS NOT FOR
	// PRODUCTION USE.
	testKeySeedString = "origin-protocol-v0-fixture-signing-key"

	// Fixed timestamps and identifiers used across the fixture so the
	// generated outputs are deterministic.
	fixtureObservedAt  = "2026-01-01T00:00:00Z"
	fixtureIngestedAt  = "2026-01-01T00:00:00Z"
	fixtureEvidenceID  = "0000000000000000000000000000000000000000000000000000000000000001"
	fixtureSubject     = "pkg:npm/example@1.0.0"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("✓ fixtures generated")
}

func run() error {
	// 1. Test signing key.
	priv, pub, fp, err := testKey()
	if err != nil {
		return err
	}
	if err := os.MkdirAll("keys", 0755); err != nil {
		return err
	}
	if err := os.WriteFile("keys/test-signer.pub", []byte(pub), 0644); err != nil {
		return err
	}
	if err := os.WriteFile("keys/test-signer.ed25519", []byte(priv), 0644); err != nil {
		return err
	}

	// 2. Identity envelopes.
	observation := assertion.Identity{
		Subject:    fixtureSubject,
		Predicate:  "registry_reports_signing_key",
		Object:     assertion.Object{Kind: assertion.ObjectIRI, IRI: "npm:key:fixture-key"},
		EvidenceID: fixtureEvidenceID,
		ObservedAt: fixtureObservedAt,
		Normalizer: "fixture-normalizer@v0.1.0",
		Vocab:      "v5",
	}
	if err := emitIdentity("identity/observation", observation); err != nil {
		return err
	}

	verified := assertion.Identity{
		Subject:    fixtureSubject,
		Predicate:  "cryptographically_verified_signature_by",
		Object:     assertion.Object{Kind: assertion.ObjectIRI, IRI: "sigstore:fulcio:fixture-identity"},
		EvidenceID: fixtureEvidenceID,
		ObservedAt: fixtureObservedAt,
		Normalizer: "fixture-verifier@v0.1.0",
		Vocab:      "v5",
	}
	if err := emitIdentity("identity/verified", verified); err != nil {
		return err
	}

	// 3. Occurrence envelopes.
	obsID, _ := observation.ComputeID()
	verID, _ := verified.ComputeID()
	logID := "log:" + fp

	observer := assertion.Occurrence{
		IdentityID:    obsID,
		Attestor:      "ingestor:fixture@v0.1.0:" + fp,
		AttestorRole:  assertion.RoleObserver,
		IngestedAt:    fixtureIngestedAt,
		LogID:         logID,
		PrevChainHash: "0000000000000000000000000000000000000000000000000000000000000000",
	}
	if err := emitOccurrence("occurrence/observer", &observer, priv, fp); err != nil {
		return err
	}

	// federated_importer occurrence cites a peer_reports_* identity so
	// the no-laundering rule is satisfied. Build that identity here.
	peerReports := assertion.Identity{
		Subject:    fixtureSubject,
		Predicate:  "peer_reports_cryptographic_verification_of",
		Object:     assertion.Object{Kind: assertion.ObjectRef, Ref: verID},
		EvidenceID: fixtureEvidenceID,
		ObservedAt: fixtureObservedAt,
		Normalizer: "federation-import@v0.1.0",
		Vocab:      "v5",
	}
	prID, _ := peerReports.ComputeID()
	if err := emitIdentity("identity/peer_reports", peerReports); err != nil {
		return err
	}

	federated := assertion.Occurrence{
		IdentityID:    prID,
		Attestor:      "peer:log:fixture-peer",
		AttestorRole:  assertion.RoleFederatedImporter,
		IngestedAt:    "2026-01-02T00:00:00Z",
		LogID:         logID,
		PrevChainHash: observer.PrevChainHash, // genesis, for the sake of a standalone fixture
	}
	if err := emitOccurrence("occurrence/federated_importer", &federated, priv, fp); err != nil {
		return err
	}

	// 4. Raw evidence record.
	rawBytes := []byte("origin-protocol-v0 fixture payload bytes\n")
	rawHashBytes := sha256.Sum256(rawBytes)
	rawHash := hex.EncodeToString(rawHashBytes[:])
	if err := os.MkdirAll("raw-evidence", 0755); err != nil {
		return err
	}
	if err := os.WriteFile("raw-evidence/sample-payload.bin", rawBytes, 0644); err != nil {
		return err
	}
	if err := os.WriteFile("raw-evidence/sample-payload.expected-hash", []byte(rawHash+"\n"), 0644); err != nil {
		return err
	}

	// 5. TrustClaim envelope. Hand-construct since the eval pipeline
	// requires a full data dir; we just need the canonicalization shape.
	claim := map[string]any{
		"subject":         fixtureSubject,
		"policy_id":       "fixture-policy",
		"policy_version":  "v1",
		"policy_hash":     "1111111111111111111111111111111111111111111111111111111111111111",
		"query":           "data.fixture.verdict",
		"verdict":         "trusted",
		"qualifiers":      []string{"a_qualifier", "another_qualifier"},
		// The five fields that the v0 spec §5.3 EXCLUDES from canonical
		// bytes are present in the JSON record but stripped at hash time.
		"evaluated_at":              "2026-01-01T00:00:01Z",
		"projection_manifest_hash":  "abc123",
		"identities_hash":           "def456",
		"evaluator_version":         "fixture-evaluator@v0.1.0",
		"vocab_version":             "v5",
		"normalizer_versions":       map[string]string{"fixture-normalizer": "v0.1.0"},
		"identity_ids_consumed":     []string{obsID},
		"raw_evidence_ids_consumed": []string{rawHash},
		"derivation": map[string]any{
			"rules_fired":        []string{"a_rule"},
			"missing_predicates": nil,
			"input_counts":       map[string]int{"registry_reports_signing_key": 1},
			"occurrences_cited":  map[string][]string{obsID: {observer.ID}},
		},
	}
	if err := emitClaim("claim/sample", claim); err != nil {
		return err
	}

	// 6. Phase-5 anchor fixture: signed checkpoint + synthetic provider
	// response + the anchor identity that references both.
	if err := emitAnchorFixture(priv, fp, logID); err != nil {
		return err
	}

	return nil
}

// emitAnchorFixture writes:
//   anchor/checkpoint.json            signed checkpoint (canonical bytes)
//   anchor/checkpoint.canonical-bytes JCS canonical bytes of the signed envelope
//   anchor/checkpoint.expected-iri    "checkpoint:<sha256>"
//   anchor/provider-response.json     synthetic transparency-system response
//   anchor/provider-response.expected-hash
//   anchor/anchor-identity.json       transparency_log_records_checkpoint identity
//   anchor/anchor-identity.canonical-bytes
//   anchor/anchor-identity.expected-id
func emitAnchorFixture(priv ed25519.PrivateKey, fp, logID string) error {
	if err := os.MkdirAll("anchor", 0755); err != nil {
		return err
	}

	// Synthetic Checkpoint. seq=1 + a deterministic chain_hash chosen so
	// the fixture is reproducible.
	env := checkpoint.Envelope{
		LogID:     logID,
		Seq:       1,
		ChainHash: "1111111111111111111111111111111111111111111111111111111111111111",
		SignedAt:  fixtureObservedAt,
	}
	sig, err := env.Sign(priv, fp)
	if err != nil {
		return err
	}
	signed := checkpoint.Signed{Checkpoint: env, Signature: sig}
	signedCanonical, err := signed.SignedCanonicalBytes()
	if err != nil {
		return err
	}
	ckptIRI, err := signed.IRI()
	if err != nil {
		return err
	}
	if err := os.WriteFile("anchor/checkpoint.canonical-bytes", signedCanonical, 0644); err != nil {
		return err
	}
	if err := os.WriteFile("anchor/checkpoint.expected-iri", []byte(ckptIRI+"\n"), 0644); err != nil {
		return err
	}
	// Also write a human-readable pretty form for inspection.
	pretty, _ := json.MarshalIndent(signed, "", "  ")
	if err := os.WriteFile("anchor/checkpoint.json", pretty, 0644); err != nil {
		return err
	}

	// Synthetic provider response.
	providerResp := []byte(`{"logIndex":1,"integratedTime":"1736000000","entryUUID":"fixture-entry-1"}` + "\n")
	respHash := sha256.Sum256(providerResp)
	respHashHex := hex.EncodeToString(respHash[:])
	if err := os.WriteFile("anchor/provider-response.json", providerResp, 0644); err != nil {
		return err
	}
	if err := os.WriteFile("anchor/provider-response.expected-hash", []byte(respHashHex+"\n"), 0644); err != nil {
		return err
	}

	// Anchor identity: subject = checkpoint IRI; predicate =
	// transparency_log_records_checkpoint; evidence_id = sha256 of the
	// provider response bytes.
	anchorID := assertion.Identity{
		Subject:    ckptIRI,
		Predicate:  "transparency_log_records_checkpoint",
		Object:     assertion.Object{Kind: assertion.ObjectIRI, IRI: "fakelog:fixture:1"},
		EvidenceID: respHashHex,
		ObservedAt: fixtureObservedAt,
		Normalizer: "transparency-anchor-recorder@v0.1.0",
		Vocab:      "v6",
	}
	return emitIdentity("anchor/anchor-identity", anchorID)
}

func testKey() (priv ed25519.PrivateKey, pub ed25519.PublicKey, fp string, err error) {
	seed := sha256.Sum256([]byte(testKeySeedString))
	priv = ed25519.NewKeyFromSeed(seed[:])
	pub = priv.Public().(ed25519.PublicKey)
	pubHash := sha256.Sum256(pub)
	fp = hex.EncodeToString(pubHash[:])[:16]
	return
}

func emitIdentity(prefix string, i assertion.Identity) error {
	if err := os.MkdirAll(filepath.Dir(prefix), 0755); err != nil {
		return err
	}
	id, err := i.ComputeID()
	if err != nil {
		return err
	}
	i.ID = id
	canonical, err := i.CanonicalBytes()
	if err != nil {
		return err
	}
	jsonBytes, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(prefix+".json", jsonBytes, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(prefix+".canonical-bytes", canonical, 0644); err != nil {
		return err
	}
	return os.WriteFile(prefix+".expected-id", []byte(id+"\n"), 0644)
}

func emitOccurrence(prefix string, o *assertion.Occurrence, priv ed25519.PrivateKey, fp string) error {
	if err := os.MkdirAll(filepath.Dir(prefix), 0755); err != nil {
		return err
	}
	id, err := o.ComputeID()
	if err != nil {
		return err
	}
	o.ID = id
	canonical, err := o.CanonicalBytes()
	if err != nil {
		return err
	}
	sig, err := o.Sign(priv, fp)
	if err != nil {
		return err
	}
	o.Signature = sig
	chainHash, err := assertion.ComputeOccurrenceChainHash(o.PrevChainHash, id)
	if err != nil {
		return err
	}
	o.ChainHash = chainHash
	jsonBytes, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(prefix+".json", jsonBytes, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(prefix+".canonical-bytes", canonical, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(prefix+".expected-id", []byte(id+"\n"), 0644); err != nil {
		return err
	}
	return os.WriteFile(prefix+".expected-signature", []byte(sig+"\n"), 0644)
}

func emitClaim(prefix string, claim map[string]any) error {
	if err := os.MkdirAll(filepath.Dir(prefix), 0755); err != nil {
		return err
	}
	// Canonical bytes for a claim: per spec §5.3, exclude id/signature/
	// evaluated_at/projection_manifest_hash/identities_hash and
	// derivation.occurrences_cited.
	cb, err := canonicalizeClaim(claim)
	if err != nil {
		return err
	}
	h := sha256.Sum256(cb)
	id := hex.EncodeToString(h[:])
	claim["id"] = id
	jsonBytes, err := json.MarshalIndent(claim, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(prefix+".json", jsonBytes, 0644); err != nil {
		return err
	}
	if err := os.WriteFile(prefix+".canonical-bytes", cb, 0644); err != nil {
		return err
	}
	return os.WriteFile(prefix+".expected-id", []byte(id+"\n"), 0644)
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
