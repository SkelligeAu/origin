// Package peerimport implements `origin import-occurrences`.
//
// At the import boundary, foreign occurrences are signature-verified
// against the registered peer public key, chain-validated, and routed by
// the verification class of their referenced identity:
//
//   - observation/structural class → foreign identity stored locally;
//     foreign occurrence preserved verbatim in foreign/<peer-log-id>/.
//   - verification/refutation  class → foreign identity NOT stored;
//     a NEW LOCAL identity with predicate peer_reports_<class>_of (object
//     = ref to foreign identity ID) is created and a LOCAL occurrence
//     (federated_importer role, our signature) is appended. The foreign
//     occurrence STILL goes into foreign/<peer-log-id>/ so the foreign
//     chain stays intact.
//
// See memory/layer-3.5.md §1, §3 for the rewrite rule.
// Invariant 16 (verified-form locality) is what this rule defends.
package peerimport

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fitzee/origin/internal/assertion"
	"github.com/fitzee/origin/internal/keys"
	"github.com/fitzee/origin/internal/peers"
	"github.com/fitzee/origin/internal/raw"
	"github.com/fitzee/origin/internal/vocab"
)

// FederationImportNormalizer is the normalizer version recorded on
// locally-emitted rewritten identities. It identifies the import pipeline
// as the producer of peer_reports_* identities.
const FederationImportNormalizer = "federation-import@v0.1.0"

// Importer orchestrates one foreign-log import.
type Importer struct {
	DataDir       string
	Idents        *assertion.IdentityStore
	LocalOccs     *assertion.OccurrenceLog
	RawStore      *raw.Store
	Vocab         *vocab.Vocabulary
	Ring          *keys.Ring
	Registry      *peers.Registry
	LocalAttestor string
}

// Result summarises what an import produced.
type Result struct {
	ForeignIdentitiesRead     int
	ForeignOccurrencesRead    int
	ObservationsImported      int
	VerificationsRewritten    int
	LocalOccurrencesEmitted   int
	Skipped                   int
}

// ImportDir runs the full import against a peer's data archive. The
// archive is expected to contain assertions/identities/*.jsonl and
// assertions/occurrences/local/*.jsonl + chain.log.
func (im *Importer) ImportDir(path, peerLogID string, peerKey ed25519.PublicKey) (*Result, error) {
	if peerLogID == "" {
		return nil, errors.New("peer-log-id is required")
	}
	if im.LocalOccs.LogID == peerLogID {
		return nil, fmt.Errorf("refusing to import: peer-log-id %q equals local log_id (collision; specify a different log_id via data/log-id.txt)", peerLogID)
	}
	if err := im.Registry.RegisterIfAbsent(peerLogID, peerKey); err != nil {
		return nil, fmt.Errorf("peer registration: %w", err)
	}

	// Foreign data layout: <path>/assertions/identities/ + occurrences/local/
	identDir := filepath.Join(path, "assertions", "identities")
	occDir := filepath.Join(path, "assertions", "occurrences", "local")

	foreignIdents, err := readForeignIdentities(identDir)
	if err != nil {
		return nil, fmt.Errorf("read foreign identities: %w", err)
	}
	foreignOccs, err := readForeignOccurrences(occDir)
	if err != nil {
		return nil, fmt.Errorf("read foreign occurrences: %w", err)
	}

	res := &Result{
		ForeignIdentitiesRead:  len(foreignIdents),
		ForeignOccurrencesRead: len(foreignOccs),
	}

	// Build identity index for fast lookup.
	identByID := make(map[string]assertion.Identity, len(foreignIdents))
	for _, id := range foreignIdents {
		if err := id.VerifyID(); err != nil {
			return nil, fmt.Errorf("foreign identity %s: %w", id.ID, err)
		}
		identByID[id.ID] = id
	}

	// Set up the foreign occurrence log (separate chain segment per peer).
	foreignOccsDir := filepath.Join(im.DataDir, "assertions", "occurrences", "foreign",
		filenameSafe(peerLogID))
	foreignLog, err := assertion.NewOccurrenceLog(foreignOccsDir, peerLogID)
	if err != nil {
		return nil, err
	}

	keyResolver := func(fp string) (ed25519.PublicKey, error) {
		// At import time, the only valid signer for foreign occurrences
		// is the registered peer. Reject any other fingerprint.
		return peerKey, nil
	}

	now := func() string { return time.Now().UTC().Format(time.RFC3339) }

	for _, occ := range foreignOccs {
		// Sanity: this occurrence claims to belong to peerLogID.
		if occ.LogID != peerLogID {
			return nil, fmt.Errorf("foreign occurrence %s has log_id %q, expected %q", occ.ID, occ.LogID, peerLogID)
		}
		if err := occ.VerifyID(); err != nil {
			return nil, fmt.Errorf("foreign occurrence %s: %w", occ.ID, err)
		}
		if err := occ.VerifySignature(keyResolver); err != nil {
			return nil, fmt.Errorf("foreign occurrence %s: %w", occ.ID, err)
		}
		// Look up the foreign identity this occurrence names.
		foreignID, ok := identByID[occ.IdentityID]
		if !ok {
			return nil, fmt.Errorf("foreign occurrence %s names unknown identity %s — peer archive incomplete?", occ.ID, occ.IdentityID)
		}

		// Persist foreign occurrence bytes as raw evidence so the peer
		// signature can be re-verified by an auditor against the original.
		occBytes, _ := json.Marshal(occ)
		_, _ = im.RawStore.Put(raw.Metadata{
			Source:         "foreign.occurrence",
			Endpoint:       "import:" + peerLogID + "/" + occ.ID,
			RequestParams:  map[string]string{"peer_log_id": peerLogID, "occurrence_id": occ.ID},
			FetchedAt:      now(),
			Fetcher:        im.LocalAttestor,
			ResponseStatus: 200,
		}, occBytes, im.signer(), im.keyFP())

		class := im.Vocab.VerificationClass(foreignID.Predicate)
		switch class {
		case "observation", "structural":
			// Store the foreign identity verbatim (content-addressed —
			// idempotent if we already have it). The foreign occurrence
			// goes into the foreign chain unchanged.
			if _, err := im.Idents.Put(foreignID); err != nil {
				return nil, fmt.Errorf("store foreign identity %s: %w", foreignID.ID, err)
			}
			if err := foreignLog.WriteVerbatim(occ); err != nil {
				return nil, fmt.Errorf("write foreign occurrence %s: %w", occ.ID, err)
			}
			res.ObservationsImported++

		case "verification", "refutation":
			// Boundary rewrite (invariant 16). DO NOT store the foreign
			// identity locally. The foreign occurrence still goes into
			// the foreign chain so chain integrity holds, but no local
			// projection row will appear for the verification-class
			// identity (the importer simply doesn't store it).
			if err := foreignLog.WriteVerbatim(occ); err != nil {
				return nil, fmt.Errorf("write foreign occurrence %s: %w", occ.ID, err)
			}
			// Compute the rewritten predicate.
			var rewritten string
			switch class {
			case "verification":
				rewritten = "peer_reports_cryptographic_verification_of"
			case "refutation":
				rewritten = "peer_reports_cryptographic_verification_failed_of"
			}
			localID := assertion.Identity{
				Subject:    foreignID.Subject,
				Predicate:  rewritten,
				Object:     assertion.Object{Kind: assertion.ObjectRef, Ref: foreignID.ID},
				EvidenceID: contentHash(occBytes),
				ObservedAt: occ.IngestedAt, // peer's claim time = our observation time
				Normalizer: FederationImportNormalizer,
				Vocab:      im.Vocab.Version,
			}
			stored, err := im.Idents.Put(localID)
			if err != nil {
				return nil, fmt.Errorf("store rewritten identity: %w", err)
			}
			// Emit a LOCAL occurrence with attestor_role=federated_importer.
			// Attestor records that this came from a peer; signature is
			// ours (we wrote it down).
			_, err = im.LocalOccs.Append(
				stored.ID,
				"peer:"+peerLogID,
				assertion.RoleFederatedImporter,
				im.signer(), im.keyFP(),
			)
			if err != nil {
				return nil, fmt.Errorf("append federated_importer occurrence: %w", err)
			}
			res.VerificationsRewritten++
			res.LocalOccurrencesEmitted++

		default:
			return nil, fmt.Errorf("foreign identity %s has unknown verification_class %q for predicate %q", foreignID.ID, class, foreignID.Predicate)
		}
	}
	return res, nil
}

func (im *Importer) signer() ed25519.PrivateKey {
	p, _ := im.Ring.Signer()
	return p
}

func (im *Importer) keyFP() string {
	_, f := im.Ring.Signer()
	return f
}

// readForeignIdentities reads all *.jsonl files under dir and returns
// each identity record. File-order, not chain-order (identities have no
// chain).
func readForeignIdentities(dir string) ([]assertion.Identity, error) {
	files, err := jsonlFiles(dir)
	if err != nil {
		return nil, err
	}
	var out []assertion.Identity
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 4*1024*1024), 16*1024*1024)
		for sc.Scan() {
			var id assertion.Identity
			if err := json.Unmarshal(sc.Bytes(), &id); err != nil {
				fh.Close()
				return nil, fmt.Errorf("%s: %w", f, err)
			}
			out = append(out, id)
		}
		if err := sc.Err(); err != nil && !errors.Is(err, io.EOF) {
			fh.Close()
			return nil, err
		}
		fh.Close()
	}
	return out, nil
}

// readForeignOccurrences reads occurrences in chain order (defined by
// the foreign chain.log).
func readForeignOccurrences(dir string) ([]assertion.Occurrence, error) {
	// First, build an index id→occurrence across all JSONL files.
	files, err := jsonlFiles(dir)
	if err != nil {
		return nil, err
	}
	index := make(map[string]assertion.Occurrence)
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 4*1024*1024), 16*1024*1024)
		for sc.Scan() {
			var o assertion.Occurrence
			if err := json.Unmarshal(sc.Bytes(), &o); err != nil {
				fh.Close()
				return nil, fmt.Errorf("%s: %w", f, err)
			}
			index[o.ID] = o
		}
		if err := sc.Err(); err != nil && !errors.Is(err, io.EOF) {
			fh.Close()
			return nil, err
		}
		fh.Close()
	}
	// Walk chain.log to get the chain order.
	chainPath := filepath.Join(dir, "chain.log")
	chainBytes, err := os.ReadFile(chainPath)
	if err != nil {
		return nil, fmt.Errorf("read foreign chain.log: %w", err)
	}
	var out []assertion.Occurrence
	for _, line := range strings.Split(strings.TrimRight(string(chainBytes), "\n"), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 4 {
			return nil, fmt.Errorf("malformed chain line: %q", line)
		}
		occID := parts[2]
		o, ok := index[occID]
		if !ok {
			return nil, fmt.Errorf("chain references occurrence %s not present in JSONL files", occID)
		}
		out = append(out, o)
	}
	return out, nil
}

func jsonlFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(e.Name(), ".jsonl") {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out, nil
}

func contentHash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func filenameSafe(s string) string {
	return strings.ReplaceAll(s, ":", "_")
}
