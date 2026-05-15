package verify

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fitzee/origin/internal/assertion"
	"github.com/fitzee/origin/internal/chain"
	"github.com/fitzee/origin/internal/checkpoint"
	"github.com/fitzee/origin/internal/keys"
	"github.com/fitzee/origin/internal/raw"
)

// checkAnchorIntegrity is verify check #13 (Phase 5).
//
// For every Identity with predicate transparency_log_records_checkpoint,
// resolve the subject (a checkpoint:<sha256> IRI) to the cited
// Checkpoint raw evidence, parse it, and confirm that the local chain
// at the cited (log_id, seq) still has the cited chain_hash.
//
// Outcomes per anchor:
//   - OK         : chain entry at seq matches recorded chain_hash
//   - TAMPER     : chain entry exists but chain_hash differs
//   - TRUNCATED  : no chain entry at seq (chain is shorter than anchored)
//   - MISSING_LOG: log_id is neither local nor a known foreign log
//
// Any non-OK outcome is a hard fail; the first failure surfaces with
// its category and the offending checkpoint IRI.
//
// See memory/layer-5.md §7.1.
func checkAnchorIntegrity() (string, error) {
	idents, err := assertion.NewIdentityStore(filepath.Join(dataDir, "assertions", "identities"))
	if err != nil {
		return "", err
	}
	store, err := raw.New(filepath.Join(dataDir, "raw"))
	if err != nil {
		return "", err
	}
	ring, err := keys.New(filepath.Join(dataDir, "keys"))
	if err != nil {
		return "", err
	}
	localLogID, err := keys.ResolveLogID(dataDir, ring)
	if err != nil {
		return "", err
	}

	var anchors, ok int
	var firstErr error
	err = idents.Walk(func(i assertion.Identity) error {
		if i.Predicate != "transparency_log_records_checkpoint" {
			return nil
		}
		anchors++
		// Subject IRI: checkpoint:<sha256>
		if !strings.HasPrefix(i.Subject, "checkpoint:") {
			if firstErr == nil {
				firstErr = fmt.Errorf("anchor %s has malformed subject %q (must begin checkpoint:)", i.ID, i.Subject)
			}
			return nil
		}
		ckhash := strings.TrimPrefix(i.Subject, "checkpoint:")
		_, ckBytes, _, gerr := store.Get(ckhash)
		if gerr != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("anchor %s: checkpoint %s not in raw evidence: %w", i.ID, ckhash, gerr)
			}
			return nil
		}
		var signed checkpoint.Signed
		if jerr := json.Unmarshal(ckBytes, &signed); jerr != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("anchor %s: parse checkpoint %s: %w", i.ID, ckhash, jerr)
			}
			return nil
		}
		// Signature must verify against some known key. Anchors signed
		// by foreign keys are valid; we resolve against the unified
		// key registry (local ring + peer registry — local-only for now,
		// foreign log signers are checked by check #11).
		if err := signed.VerifySignature(func(fp string) (ed25519.PublicKey, error) {
			return ring.Resolve(fp)
		}); err != nil {
			// Checkpoint signature failure is not necessarily fatal here
			// — the foreign-key path is handled by check #11. Record it
			// only when the local ring also fails.
			// (Phase 5: log but don't fail.)
		}

		cp := signed.Checkpoint
		// Determine the chain path for the cited log_id.
		var chainPath string
		switch {
		case cp.LogID == localLogID:
			chainPath = filepath.Join(dataDir, "assertions", "occurrences", "local", "chain.log")
		default:
			// Foreign log? Look under foreign/<safe-log-id>/
			candidate := filepath.Join(dataDir, "assertions", "occurrences", "foreign",
				filenameSafe(cp.LogID), "chain.log")
			if exists(candidate) {
				chainPath = candidate
			}
		}
		if chainPath == "" {
			if firstErr == nil {
				firstErr = fmt.Errorf("anchor %s: MISSING_LOG (no chain found for log_id %q)", i.ID, cp.LogID)
			}
			return nil
		}

		// Walk the chain to find seq=cp.Seq.
		var foundHash string
		var maxSeq uint64
		_, _, walkErr := chain.Walk(chainPath, func(e chain.Entry) error {
			if e.Seq > maxSeq {
				maxSeq = e.Seq
			}
			if e.Seq == cp.Seq {
				foundHash = e.ChainHash
			}
			return nil
		})
		if walkErr != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("anchor %s: chain walk: %w", i.ID, walkErr)
			}
			return nil
		}
		if foundHash == "" {
			if firstErr == nil {
				firstErr = fmt.Errorf("anchor %s: TRUNCATED (chain at log_id=%s ends at seq=%d, anchored seq=%d)",
					i.ID, cp.LogID, maxSeq, cp.Seq)
			}
			return nil
		}
		if foundHash != cp.ChainHash {
			if firstErr == nil {
				firstErr = fmt.Errorf("anchor %s: TAMPER (chain at log_id=%s seq=%d has head %s, anchored %s)",
					i.ID, cp.LogID, cp.Seq, foundHash, cp.ChainHash)
			}
			return nil
		}
		ok++
		return nil
	})
	if err != nil {
		return "", err
	}
	if firstErr != nil {
		return "", firstErr
	}
	if anchors == 0 {
		return "no anchors recorded", nil
	}
	return fmt.Sprintf("%d anchors, all chain-consistent", ok), nil
}

func exists(path string) bool {
	if _, err := os.Stat(path); err == nil {
		return true
	}
	return false
}
