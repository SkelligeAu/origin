package v0fixtures

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/SkelligeAu/origin/internal/assertion"
	"github.com/SkelligeAu/origin/internal/chain"
	"github.com/SkelligeAu/origin/internal/keys"
	"github.com/SkelligeAu/origin/internal/peerimport"
	"github.com/SkelligeAu/origin/internal/peers"
	"github.com/SkelligeAu/origin/internal/raw"
	"github.com/SkelligeAu/origin/internal/vocab"
)

// TestFederation_RewriteRule exercises the protocol's core federation
// invariant end-to-end: a peer's verification-class identity does NOT
// land in the local verified-form table; it lands as a peer_reports_*
// observation identity, cited by a federated_importer-role local
// occurrence.
//
// Builds peer-a + peer-b archives in a temp directory from deterministic
// inputs, runs the importer, and asserts on the resulting state.
func TestFederation_RewriteRule(t *testing.T) {
	tmp := t.TempDir()
	peerADir := filepath.Join(tmp, "peer-a")
	peerBDir := filepath.Join(tmp, "peer-b")

	// Construct two deterministic keys.
	privA, pubA, fpA := deriveKey(t, "origin-protocol-v0-fixture-federation-peer-a")
	privB, pubB, fpB := deriveKey(t, "origin-protocol-v0-fixture-federation-peer-b")
	logA := "log:" + fpA
	logB := "log:" + fpB

	// Build peer-b: one verification-class identity, one verifier-role
	// occurrence. Peer-a does not produce identities of its own for this
	// test; we just bootstrap a's directory layout and let the importer
	// add peer-b's data.
	verifiedID := assertion.Identity{
		Subject:    "pkg:fixture/example@1.0.0",
		Predicate:  "cryptographically_verified_signature_by",
		Object:     assertion.Object{Kind: assertion.ObjectIRI, IRI: "sigstore:fulcio:federation-fixture-id"},
		EvidenceID: "0000000000000000000000000000000000000000000000000000000000000042",
		ObservedAt: "2026-01-01T00:00:00Z",
		Normalizer: "fixture-verifier@v0.1.0",
		Vocab:      "v5",
	}
	verifiedIDHash, _ := verifiedID.ComputeID()
	verifiedID.ID = verifiedIDHash

	verifiedOcc := assertion.Occurrence{
		IdentityID:    verifiedIDHash,
		Attestor:      "ingestor:fixture@v0.1.0:" + fpB,
		AttestorRole:  assertion.RoleVerifier,
		IngestedAt:    "2026-01-02T00:00:00Z",
		LogID:         logB,
		PrevChainHash: chain.Genesis,
	}
	occID, _ := verifiedOcc.ComputeID()
	verifiedOcc.ID = occID
	sig, _ := verifiedOcc.Sign(privB, fpB)
	verifiedOcc.Signature = sig
	chainHash, _ := assertion.ComputeOccurrenceChainHash(chain.Genesis, occID)
	verifiedOcc.ChainHash = chainHash

	writePeerArchive(t, peerBDir, verifiedID, verifiedOcc, logB)

	// Bootstrap peer-a directory layout.
	bootstrapEmptyArchive(t, peerADir, privA, pubA, fpA, logA)

	// Run the importer: peer-a imports peer-b. The importer takes the
	// peer's `data` directory, not the parent archive folder.
	importPeerInto(t, peerADir, filepath.Join(peerBDir, "data"), logB, pubB)

	// Assertions on peer-a's post-import state.
	identsDir := filepath.Join(peerADir, "data", "assertions", "identities")
	idents, err := assertion.NewIdentityStore(identsDir)
	if err != nil {
		t.Fatal(err)
	}
	// The peer's verified-form identity MUST NOT be in peer-a's local
	// identity store.
	if _, ok, err := idents.Find(verifiedIDHash); err != nil {
		t.Fatal(err)
	} else if ok {
		t.Fatalf("LAUNDERING: peer's verification-class identity %s WAS stored locally", verifiedIDHash)
	}

	// A peer_reports_cryptographic_verification_of identity MUST exist
	// locally, referencing the foreign identity ID.
	var found bool
	err = idents.Walk(func(i assertion.Identity) error {
		if i.Predicate != "peer_reports_cryptographic_verification_of" {
			return nil
		}
		if i.Object.Kind != assertion.ObjectRef {
			t.Errorf("peer_reports_* identity has wrong object.kind: %s", i.Object.Kind)
			return nil
		}
		if i.Object.Ref != verifiedIDHash {
			t.Errorf("peer_reports_* identity object.ref = %s, want %s", i.Object.Ref, verifiedIDHash)
		}
		found = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatal("expected peer_reports_cryptographic_verification_of identity in peer-a; not found")
	}

	// Peer-a's local log MUST contain a federated_importer occurrence
	// citing the peer_reports_* identity.
	localLog, err := assertion.NewOccurrenceLog(
		filepath.Join(peerADir, "data", "assertions", "occurrences", "local"), logA)
	if err != nil {
		t.Fatal(err)
	}
	var fedFound int
	err = localLog.Walk(func(o assertion.Occurrence) error {
		if o.AttestorRole == assertion.RoleFederatedImporter {
			fedFound++
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if fedFound != 1 {
		t.Errorf("expected exactly 1 federated_importer occurrence in peer-a's local log, got %d", fedFound)
	}

	// Peer-b's verifier-role occurrence MUST be preserved verbatim in
	// peer-a's foreign log under peer-b's log_id.
	foreignLog, err := assertion.NewOccurrenceLog(
		filepath.Join(peerADir, "data", "assertions", "occurrences", "foreign", strings.ReplaceAll(logB, ":", "_")),
		logB,
	)
	if err != nil {
		t.Fatal(err)
	}
	var foreignFound int
	err = foreignLog.Walk(func(o assertion.Occurrence) error {
		foreignFound++
		// Signature MUST still be peer-b's.
		if err := o.VerifySignature(func(_ string) (ed25519.PublicKey, error) {
			return pubB, nil
		}); err != nil {
			t.Errorf("foreign occurrence signature does not verify against peer-b's key: %v", err)
		}
		// Attestor role MUST be unchanged.
		if o.AttestorRole != assertion.RoleVerifier {
			t.Errorf("foreign occurrence attestor_role = %s, want verifier", o.AttestorRole)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if foreignFound != 1 {
		t.Errorf("expected exactly 1 occurrence in peer-a's foreign log, got %d", foreignFound)
	}
}

// --- helpers ---

func deriveKey(t *testing.T, seedString string) (ed25519.PrivateKey, ed25519.PublicKey, string) {
	t.Helper()
	seed := sha256.Sum256([]byte(seedString))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	pubHash := sha256.Sum256(pub)
	fp := hex.EncodeToString(pubHash[:])[:16]
	return priv, pub, fp
}

// writePeerArchive writes a minimal data tree for a peer: one identity
// + one occurrence + chain.log + ingestor.pub.
func writePeerArchive(t *testing.T, dir string, id assertion.Identity, occ assertion.Occurrence, _ string) {
	t.Helper()
	dataDir := filepath.Join(dir, "data")
	idDir := filepath.Join(dataDir, "assertions", "identities")
	occDir := filepath.Join(dataDir, "assertions", "occurrences", "local")
	keyDir := filepath.Join(dataDir, "keys")
	for _, d := range []string{idDir, occDir, keyDir} {
		if err := os.MkdirAll(d, 0755); err != nil {
			t.Fatal(err)
		}
	}
	// Identity.
	idJSON, _ := json.Marshal(id)
	if err := os.WriteFile(filepath.Join(idDir, "2026-01-01.jsonl"), append(idJSON, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
	// Occurrence + chain.log.
	occJSON, _ := json.Marshal(occ)
	if err := os.WriteFile(filepath.Join(occDir, "2026-01-02.jsonl"), append(occJSON, '\n'), 0644); err != nil {
		t.Fatal(err)
	}
	chainLine := []byte("1\t" + occ.PrevChainHash + "\t" + occ.ID + "\t" + occ.ChainHash + "\n")
	if err := os.WriteFile(filepath.Join(occDir, "chain.log"), chainLine, 0644); err != nil {
		t.Fatal(err)
	}
}

// bootstrapEmptyArchive creates a minimal peer-a data tree so the
// importer has something to write into.
func bootstrapEmptyArchive(t *testing.T, dir string, priv ed25519.PrivateKey, pub ed25519.PublicKey, fp, logID string) {
	t.Helper()
	dataDir := filepath.Join(dir, "data")
	for _, sub := range []string{
		filepath.Join("assertions", "identities"),
		filepath.Join("assertions", "occurrences", "local"),
		"keys", "raw", "peers", "projections",
	} {
		if err := os.MkdirAll(filepath.Join(dataDir, sub), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dataDir, "keys", "ingestor.pub"), pub, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "keys", "ingestor.ed25519"), priv, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "log-id.txt"), []byte(logID), 0644); err != nil {
		t.Fatal(err)
	}
}

func importPeerInto(t *testing.T, peerADir, peerBDir, peerBLogID string, peerBPub ed25519.PublicKey) {
	t.Helper()
	dataDir := filepath.Join(peerADir, "data")

	v, err := vocab.LoadLatest(filepath.Join("..", "..", "vocab"))
	if err != nil {
		t.Fatal(err)
	}
	idents, err := assertion.NewIdentityStore(filepath.Join(dataDir, "assertions", "identities"))
	if err != nil {
		t.Fatal(err)
	}
	idents.WithVocab(v)

	// Build peer-a's signing key from the ed25519 file we just wrote.
	keyBytes, err := os.ReadFile(filepath.Join(dataDir, "keys", "ingestor.ed25519"))
	if err != nil {
		t.Fatal(err)
	}
	pubA := ed25519.PrivateKey(keyBytes).Public().(ed25519.PublicKey)
	pubAHash := sha256.Sum256(pubA)
	fpA := hex.EncodeToString(pubAHash[:])[:16]
	logA := "log:" + fpA

	// Mimic keys.Ring just enough to satisfy the importer's needs.
	localOccs, err := assertion.NewOccurrenceLog(
		filepath.Join(dataDir, "assertions", "occurrences", "local"), logA)
	if err != nil {
		t.Fatal(err)
	}
	rawStore, err := raw.New(filepath.Join(dataDir, "raw"))
	if err != nil {
		t.Fatal(err)
	}
	registry, err := peers.New(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.RegisterIfAbsent(peerBLogID, peerBPub); err != nil {
		t.Fatal(err)
	}

	// Real keys.Ring backed by the on-disk key files we wrote in
	// bootstrapEmptyArchive.
	ring, err := keys.New(filepath.Join(dataDir, "keys"))
	if err != nil {
		t.Fatal(err)
	}
	im := &peerimport.Importer{
		DataDir:       dataDir,
		Idents:        idents,
		LocalOccs:     localOccs,
		RawStore:      rawStore,
		Vocab:         v,
		Ring:          ring,
		Registry:      registry,
		LocalAttestor: "ingestor:fixture@v0.1.0:" + fpA,
	}
	_, err = im.ImportDir(peerBDir, peerBLogID, peerBPub)
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	_ = time.Now
}
