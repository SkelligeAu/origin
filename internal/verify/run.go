package verify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"

	"github.com/SkelligeAu/origin/internal/assertion"
	"github.com/SkelligeAu/origin/internal/canon"
	"github.com/SkelligeAu/origin/internal/chain"
	"github.com/SkelligeAu/origin/internal/eval"
	"github.com/SkelligeAu/origin/internal/keys"
	"github.com/SkelligeAu/origin/internal/project"
	"github.com/SkelligeAu/origin/internal/raw"
)

const dataDir = "data"

// runVerify replays the canonical state under the Phase-3 split: identity
// reproducibility, occurrence signatures + chain integrity, identity ↔
// occurrence linkage, raw evidence resolvability, projection determinism,
// claim envelope consistency, claim re-derivation determinism, and
// cryptographic re-verification. Exits non-zero on any drift.
func runVerify(args []string) error {
	checks := []struct {
		name string
		fn   func() (string, error)
	}{
		{"identity reproducibility", checkIdentities},
		{"occurrence signatures", checkOccurrenceSignatures},
		{"chain integrity (local log)", checkChain},
		{"identity ↔ occurrence linkage", checkIdentityOccurrenceLinkage},
		{"raw evidence resolvability", checkRawEvidence},
		{"projection determinism", checkProjection},
		{"claim envelope consistency", checkClaimEnvelopes},
		{"cryptographic re-verification", checkCryptoReverify},
		{"claim re-derivation determinism", checkClaimReDerivation},
		{"foreign chain integrity (per peer)", checkForeignChains},
		{"foreign occurrence signatures", checkForeignSignatures},
		{"no-laundering (federated_importer → observation only)", checkNoLaundering},
		{"anchor integrity (chain consistency)", checkAnchorIntegrity},
	}
	failed := false
	for _, c := range checks {
		summary, err := c.fn()
		if err != nil {
			failed = true
			fmt.Fprintf(os.Stderr, "✗ %s: %v\n", c.name, err)
			continue
		}
		fmt.Fprintf(os.Stderr, "✓ %s: %s\n", c.name, summary)
	}
	if failed {
		return errors.New("verify failed")
	}
	return nil
}

// checkIdentities recomputes the canonical envelope hash for every
// identity in the store and confirms it equals the stored ID. Catches
// tampering with identity content.
func checkIdentities() (string, error) {
	idents, err := assertion.NewIdentityStore(filepath.Join(dataDir, "assertions", "identities"))
	if err != nil {
		return "", err
	}
	count := 0
	var firstErr error
	err = idents.Walk(func(i assertion.Identity) error {
		count++
		if err := i.VerifyID(); err != nil && firstErr == nil {
			firstErr = err
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if firstErr != nil {
		return "", firstErr
	}
	if count == 0 {
		return "no identities to verify", nil
	}
	return fmt.Sprintf("%d identities reproducibility OK", count), nil
}

// checkOccurrenceSignatures verifies every occurrence's signature against
// the attestor's recorded key. Also confirms the occurrence ID equals the
// recomputed canonical hash.
func checkOccurrenceSignatures() (string, error) {
	ring, err := keys.New(filepath.Join(dataDir, "keys"))
	if err != nil {
		return "", err
	}
	logID, err := keys.ResolveLogID(dataDir, ring)
	if err != nil {
		return "", err
	}
	occs, err := assertion.NewOccurrenceLog(filepath.Join(dataDir, "assertions", "occurrences", "local"), logID)
	if err != nil {
		return "", err
	}
	resolver := func(fp string) (ed25519.PublicKey, error) {
		return ring.Resolve(fp)
	}
	count := 0
	var firstErr error
	err = occs.Walk(func(o assertion.Occurrence) error {
		count++
		if err := o.VerifyID(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("occurrence %s: %w", o.ID, err)
		}
		if err := o.VerifySignature(resolver); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("occurrence %s: %w", o.ID, err)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if firstErr != nil {
		return "", firstErr
	}
	if count == 0 {
		return "no occurrences to verify", nil
	}
	return fmt.Sprintf("%d occurrence signatures OK", count), nil
}

// checkChain walks chain.log per log_id and confirms each chain hash
// derives correctly from the previous.
func checkChain() (string, error) {
	chainPath := filepath.Join(dataDir, "assertions", "occurrences", "local", "chain.log")
	head, count, err := chain.Walk(chainPath, nil)
	if err != nil {
		return "", err
	}
	if count == 0 {
		return "empty chain (genesis)", nil
	}
	return fmt.Sprintf("%d entries, head=%s…", count, head[:16]), nil
}

// checkIdentityOccurrenceLinkage confirms every occurrence's identity_id
// resolves to an existing identity record.
func checkIdentityOccurrenceLinkage() (string, error) {
	idents, err := assertion.NewIdentityStore(filepath.Join(dataDir, "assertions", "identities"))
	if err != nil {
		return "", err
	}
	// Build identity index for fast lookup.
	have := map[string]struct{}{}
	if err := idents.Walk(func(i assertion.Identity) error {
		have[i.ID] = struct{}{}
		return nil
	}); err != nil {
		return "", err
	}

	ring, err := keys.New(filepath.Join(dataDir, "keys"))
	if err != nil {
		return "", err
	}
	logID, err := keys.ResolveLogID(dataDir, ring)
	if err != nil {
		return "", err
	}
	occs, err := assertion.NewOccurrenceLog(filepath.Join(dataDir, "assertions", "occurrences", "local"), logID)
	if err != nil {
		return "", err
	}
	count := 0
	missing := 0
	err = occs.Walk(func(o assertion.Occurrence) error {
		count++
		if _, ok := have[o.IdentityID]; !ok {
			missing++
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if missing > 0 {
		return "", fmt.Errorf("%d of %d occurrences reference missing identities", missing, count)
	}
	if count == 0 {
		return "no occurrences", nil
	}
	return fmt.Sprintf("%d occurrence→identity links resolved", count), nil
}

// checkRawEvidence confirms every identity's evidence_id resolves to a
// raw record whose payload hashes to its ID.
func checkRawEvidence() (string, error) {
	idents, err := assertion.NewIdentityStore(filepath.Join(dataDir, "assertions", "identities"))
	if err != nil {
		return "", err
	}
	store, err := raw.New(filepath.Join(dataDir, "raw"))
	if err != nil {
		return "", err
	}
	count := 0
	missing := 0
	err = idents.Walk(func(i assertion.Identity) error {
		count++
		_, _, _, err := store.Get(i.EvidenceID)
		if err != nil {
			missing++
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	if missing > 0 {
		return "", fmt.Errorf("%d of %d evidence references missing", missing, count)
	}
	return fmt.Sprintf("%d evidence references resolved", count), nil
}

func checkProjection() (string, error) {
	idents, err := assertion.NewIdentityStore(filepath.Join(dataDir, "assertions", "identities"))
	if err != nil {
		return "", err
	}
	ring, err := keys.New(filepath.Join(dataDir, "keys"))
	if err != nil {
		return "", err
	}
	logID, err := keys.ResolveLogID(dataDir, ring)
	if err != nil {
		return "", err
	}
	occs, err := assertion.NewOccurrenceLog(filepath.Join(dataDir, "assertions", "occurrences", "local"), logID)
	if err != nil {
		return "", err
	}
	rawStore, err := raw.New(filepath.Join(dataDir, "raw"))
	if err != nil {
		return "", err
	}
	manifestPath := filepath.Join(dataDir, "projections", "MANIFEST.json")
	recorded, err := readProjectionHash(manifestPath)
	if err != nil {
		return "", fmt.Errorf("read existing manifest: %w", err)
	}
	tmpDir, err := os.MkdirTemp("", "origin-verify-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmpDir)
	tmpProj := project.New(tmpDir)
	foreign, err := project.DiscoverForeignOccurrenceLogs(dataDir)
	if err != nil {
		return "", err
	}
	if err := tmpProj.Build(idents, occs, foreign, rawStore); err != nil {
		return "", err
	}
	rebuilt, err := readProjectionHash(tmpProj.ManifestPath)
	if err != nil {
		return "", err
	}
	if recorded != rebuilt {
		return "", fmt.Errorf("projection drift: recorded=%s rebuilt=%s", recorded, rebuilt)
	}
	return fmt.Sprintf("projection_hash matches (%s…)", recorded[:16]), nil
}

func readProjectionHash(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return "", err
	}
	s, _ := m["projection_hash"].(string)
	if s == "" {
		return "", errors.New("manifest has no projection_hash")
	}
	return s, nil
}

func checkClaimReDerivation() (string, error) {
	dir := filepath.Join(dataDir, "claims")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return "no claims to re-derive", nil
		}
		return "", err
	}
	var checked int
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		path := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		var stored map[string]any
		if err := json.Unmarshal(b, &stored); err != nil {
			return "", err
		}
		subject, _ := stored["subject"].(string)
		policyID, _ := stored["policy_id"].(string)
		policyVersion, _ := stored["policy_version"].(string)
		storedID, _ := stored["id"].(string)
		if subject == "" || policyID == "" || policyVersion == "" {
			return "", fmt.Errorf("%s: missing subject/policy fields", path)
		}
		spec := policyID + "@" + policyVersion
		rederived, err := eval.Evaluate(subject, spec, dataDir)
		if err != nil {
			return "", fmt.Errorf("%s: re-derive: %w", path, err)
		}
		if rederived.ID != storedID {
			return "", fmt.Errorf("%s: claim ID drift (stored=%s rederived=%s)",
				path, storedID, rederived.ID)
		}
		checked++
	}
	if checked == 0 {
		return "no claims to re-derive", nil
	}
	return fmt.Sprintf("%d claims re-derived to byte-identical IDs", checked), nil
}

func checkClaimEnvelopes() (string, error) {
	dir := filepath.Join(dataDir, "claims")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return "no claims to verify", nil
		}
		return "", err
	}
	count := 0
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		path := filepath.Join(dir, e.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			return "", err
		}
		expectedID, _ := m["id"].(string)
		filenameID := e.Name()[:len(e.Name())-len(".json")]
		if expectedID != filenameID {
			return "", fmt.Errorf("%s: id field %q != filename id %q", path, expectedID, filenameID)
		}
		delete(m, "id")
		delete(m, "signature")
		delete(m, "evaluated_at")
		delete(m, "projection_manifest_hash")
		delete(m, "identities_hash")
		if d, ok := m["derivation"].(map[string]any); ok {
			delete(d, "occurrences_cited")
		}
		b2, _ := json.Marshal(m)
		cb, err := canon.CanonicalizeJSON(b2)
		if err != nil {
			return "", fmt.Errorf("%s: %w", path, err)
		}
		got := sha256.Sum256(cb)
		if hex.EncodeToString(got[:]) != expectedID {
			return "", fmt.Errorf("%s: id drift (got=%s want=%s)",
				path, hex.EncodeToString(got[:]), expectedID)
		}
		count++
	}
	return fmt.Sprintf("%d claim envelopes consistent", count), nil
}
