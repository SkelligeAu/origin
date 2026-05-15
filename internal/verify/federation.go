package verify

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fitzee/origin/internal/assertion"
	"github.com/fitzee/origin/internal/chain"
	"github.com/fitzee/origin/internal/keys"
	"github.com/fitzee/origin/internal/peers"
	"github.com/fitzee/origin/internal/vocab"
)

// foreignLogDir returns the absolute path to data/assertions/occurrences/foreign/.
func foreignLogDir() string {
	return filepath.Join(dataDir, "assertions", "occurrences", "foreign")
}

// foreignPeerLogIDs returns each peer-log-id whose foreign occurrences
// have landed locally (one subdirectory per peer).
func foreignPeerLogIDs() ([]string, error) {
	entries, err := os.ReadDir(foreignLogDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// Directory name has ":" → "_" mapping (see peers.pathFor).
		// Reverse the first underscore back to a colon to recover the
		// peer-log-id.
		name := e.Name()
		for i := 0; i < len(name); i++ {
			if name[i] == '_' {
				name = name[:i] + ":" + name[i+1:]
				break
			}
		}
		out = append(out, name)
	}
	return out, nil
}

// checkForeignChains walks chain.log for each registered peer's foreign
// log and confirms hash continuity per-log. Verify check #10.
func checkForeignChains() (string, error) {
	ids, err := foreignPeerLogIDs()
	if err != nil {
		return "", err
	}
	if len(ids) == 0 {
		return "no foreign logs", nil
	}
	var totalEntries int
	for _, peerLogID := range ids {
		dirName := filenameSafe(peerLogID)
		chainPath := filepath.Join(foreignLogDir(), dirName, "chain.log")
		head, count, err := chain.Walk(chainPath, nil)
		if err != nil {
			return "", fmt.Errorf("foreign chain %s: %w", peerLogID, err)
		}
		_ = head
		totalEntries += int(count)
	}
	return fmt.Sprintf("%d peers, %d total entries", len(ids), totalEntries), nil
}

// checkForeignSignatures verifies every foreign occurrence's signature
// against the peer's registered public key. Verify check #11.
func checkForeignSignatures() (string, error) {
	ids, err := foreignPeerLogIDs()
	if err != nil {
		return "", err
	}
	if len(ids) == 0 {
		return "no foreign occurrences", nil
	}
	registry, err := peers.New(dataDir)
	if err != nil {
		return "", err
	}
	var total int
	for _, peerLogID := range ids {
		pub, err := registry.Resolve(peerLogID)
		if err != nil {
			return "", fmt.Errorf("peer %s: %w", peerLogID, err)
		}
		log, err := assertion.NewOccurrenceLog(
			filepath.Join(foreignLogDir(), filenameSafe(peerLogID)),
			peerLogID,
		)
		if err != nil {
			return "", err
		}
		resolver := func(fp string) (ed25519.PublicKey, error) {
			return pub, nil
		}
		var firstErr error
		err = log.Walk(func(o assertion.Occurrence) error {
			total++
			if err := o.VerifyID(); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("peer %s occurrence %s: %w", peerLogID, o.ID, err)
			}
			if err := o.VerifySignature(resolver); err != nil && firstErr == nil {
				firstErr = fmt.Errorf("peer %s occurrence %s: %w", peerLogID, o.ID, err)
			}
			return nil
		})
		if err != nil {
			return "", err
		}
		if firstErr != nil {
			return "", firstErr
		}
	}
	return fmt.Sprintf("%d peers, %d foreign occurrences verified", len(ids), total), nil
}

// checkNoLaundering enforces invariant 16 structurally at verify time:
// every federated_importer-role occurrence must name an identity whose
// predicate has verification_class ∈ {observation, structural}. Any
// federated_importer occurrence naming a verification or refutation
// predicate is laundering — a violation that surfaces here even if it
// somehow bypassed the import-time check. Verify check #12.
func checkNoLaundering() (string, error) {
	v, err := vocab.LoadLatest("vocab")
	if err != nil {
		return "", err
	}
	idents, err := assertion.NewIdentityStore(filepath.Join(dataDir, "assertions", "identities"))
	if err != nil {
		return "", err
	}
	// Build identity index id → predicate.
	idPred := make(map[string]string)
	if err := idents.Walk(func(i assertion.Identity) error {
		idPred[i.ID] = i.Predicate
		return nil
	}); err != nil {
		return "", err
	}

	// Walk local + all foreign occurrence logs; check every
	// federated_importer occurrence.
	var checked, federated int
	checkOne := func(o assertion.Occurrence) error {
		checked++
		if o.AttestorRole != assertion.RoleFederatedImporter {
			return nil
		}
		federated++
		pred, ok := idPred[o.IdentityID]
		if !ok {
			return fmt.Errorf("federated_importer occurrence %s names unknown identity %s", o.ID, o.IdentityID)
		}
		class := v.VerificationClass(pred)
		if class == "verification" || class == "refutation" {
			return fmt.Errorf("LAUNDERING: federated_importer occurrence %s names predicate %q (%s class)",
				o.ID, pred, class)
		}
		return nil
	}
	// Local log.
	{
		ring, err := keys.New(filepath.Join(dataDir, "keys"))
		if err != nil {
			return "", err
		}
		logID, err := keys.ResolveLogID(dataDir, ring)
		if err != nil {
			return "", err
		}
		localOcc, err := assertion.NewOccurrenceLog(
			filepath.Join(dataDir, "assertions", "occurrences", "local"), logID)
		if err != nil {
			return "", err
		}
		if err := localOcc.Walk(checkOne); err != nil {
			return "", err
		}
	}
	// Foreign logs.
	ids, err := foreignPeerLogIDs()
	if err != nil {
		return "", err
	}
	for _, peerLogID := range ids {
		log, err := assertion.NewOccurrenceLog(
			filepath.Join(foreignLogDir(), filenameSafe(peerLogID)),
			peerLogID,
		)
		if err != nil {
			return "", err
		}
		if err := log.Walk(checkOne); err != nil {
			return "", err
		}
	}
	return fmt.Sprintf("%d occurrences walked, %d federated_importer (all observation/structural)", checked, federated), nil
}

func filenameSafe(s string) string {
	out := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			out[i] = '_'
		} else {
			out[i] = s[i]
		}
	}
	return string(out)
}
