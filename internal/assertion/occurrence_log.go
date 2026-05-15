package assertion

import (
	"bufio"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/fitzee/origin/internal/chain"
)

// OccurrenceLog is the append-only occurrence stream under
// data/assertions/occurrences/. Each occurrence advances a chain anchored
// at chain.log. The chain is per-(log_id) — see memory/layer-3.md §3.
// Day-3 single-ingestor systems still have one chain; future federation
// imports will write into additional chain segments.
type OccurrenceLog struct {
	Dir       string
	ChainPath string
	LogID     string
}

// NewOccurrenceLog returns a handle for log_id, creating the directory
// if needed.
func NewOccurrenceLog(dir, logID string) (*OccurrenceLog, error) {
	if logID == "" {
		return nil, errors.New("log_id is required")
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	return &OccurrenceLog{
		Dir:       dir,
		ChainPath: filepath.Join(dir, "chain.log"),
		LogID:     logID,
	}, nil
}

// Append signs the occurrence, writes it, advances the chain. Idempotent
// on occurrence ID: re-appending an identical occurrence is a no-op and
// returns the existing record.
//
// The caller supplies the identity_id, attestor, role, and ingested_at.
// The function fills in log_id (this log's id), prev_chain_hash (chain
// head), computes the canonical occurrence ID, signs it, then computes
// the chain_hash and writes everything.
func (l *OccurrenceLog) Append(
	identityID string,
	attestor string,
	role AttestorRole,
	priv ed25519.PrivateKey,
	keyFP string,
) (Occurrence, error) {
	prev, _, err := chain.Head(l.ChainPath)
	if err != nil {
		return Occurrence{}, err
	}
	o := Occurrence{
		IdentityID:    identityID,
		Attestor:      attestor,
		AttestorRole:  role,
		IngestedAt:    time.Now().UTC().Format(time.RFC3339),
		LogID:         l.LogID,
		PrevChainHash: prev,
	}
	id, err := o.ComputeID()
	if err != nil {
		return Occurrence{}, err
	}
	o.ID = id
	// Idempotence: if an occurrence with the same canonical content
	// already exists in this log, skip (return existing).
	if existing, ok, err := l.Find(id); err != nil {
		return Occurrence{}, err
	} else if ok {
		return existing, nil
	}
	sig, err := o.Sign(priv, keyFP)
	if err != nil {
		return Occurrence{}, err
	}
	o.Signature = sig
	chainHash, err := ComputeOccurrenceChainHash(prev, id)
	if err != nil {
		return Occurrence{}, err
	}
	o.ChainHash = chainHash
	if err := l.writeOccurrence(o); err != nil {
		return Occurrence{}, err
	}
	// Advance chain.log. Chain entry references the occurrence id (which
	// already encodes attestor + identity, so the chain naturally
	// distinguishes ingestors writing the same identity).
	prevHead, prevSeq, err := chain.Head(l.ChainPath)
	if err != nil {
		return Occurrence{}, err
	}
	// Re-derive chain_hash from the actual chain head we just read (race-
	// safe even though we're single-writer Day-3).
	if prevHead != prev {
		// Another writer advanced the chain between our Head() call and
		// our Append. Recompute and retry would be the correct response;
		// Day-3 is single-writer so this should not happen.
		return Occurrence{}, fmt.Errorf("chain advanced under us: had prev %s, now %s", prev, prevHead)
	}
	if err := chain.AppendEntry(l.ChainPath, chain.Entry{
		Seq:           prevSeq + 1,
		PrevChainHash: prev,
		AssertionID:   id, // we reuse the chain entry "assertion id" slot for the occurrence id
		ChainHash:     chainHash,
	}); err != nil {
		return Occurrence{}, err
	}
	return o, nil
}

// WriteVerbatim writes an already-shaped Occurrence (with signature and
// chain hashes already populated) to the log without re-signing. Used by
// the federation importer to preserve foreign occurrences exactly as
// their peer wrote them.
//
// The caller is responsible for chain continuity (prev_chain_hash equals
// current chain head; chain_hash correctly derived). WriteVerbatim
// validates these and refuses on mismatch.
func (l *OccurrenceLog) WriteVerbatim(o Occurrence) error {
	if o.ID == "" || o.Signature == "" || o.ChainHash == "" {
		return errors.New("WriteVerbatim requires id, signature, chain_hash already set")
	}
	if err := o.VerifyID(); err != nil {
		return fmt.Errorf("verbatim occurrence: %w", err)
	}
	prev, prevSeq, err := chain.Head(l.ChainPath)
	if err != nil {
		return err
	}
	if o.PrevChainHash != prev {
		return fmt.Errorf("verbatim occurrence prev_chain_hash %s != current chain head %s", o.PrevChainHash, prev)
	}
	want, err := ComputeOccurrenceChainHash(prev, o.ID)
	if err != nil {
		return err
	}
	if want != o.ChainHash {
		return fmt.Errorf("verbatim occurrence chain_hash %s != recomputed %s", o.ChainHash, want)
	}
	// Idempotence: same occurrence already at this position is a no-op.
	if existing, ok, err := l.Find(o.ID); err != nil {
		return err
	} else if ok {
		_ = existing
		return nil
	}
	if err := l.writeOccurrence(o); err != nil {
		return err
	}
	return chain.AppendEntry(l.ChainPath, chain.Entry{
		Seq:           prevSeq + 1,
		PrevChainHash: prev,
		AssertionID:   o.ID,
		ChainHash:     o.ChainHash,
	})
}

func (l *OccurrenceLog) writeOccurrence(o Occurrence) error {
	day, err := dayFromIngested(o.IngestedAt)
	if err != nil {
		return err
	}
	path := filepath.Join(l.Dir, day+".jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := json.Marshal(o)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	return err
}

// Find returns the occurrence with this ID, or (Occurrence{}, false, nil)
// if not present.
func (l *OccurrenceLog) Find(id string) (Occurrence, bool, error) {
	var found Occurrence
	var ok bool
	err := l.Walk(func(o Occurrence) error {
		if o.ID == id {
			found = o
			ok = true
			return errStopWalk
		}
		return nil
	})
	if errors.Is(err, errStopWalk) {
		return found, true, nil
	}
	if err != nil {
		return Occurrence{}, false, err
	}
	return Occurrence{}, ok, nil
}

// Walk visits every occurrence in chain order across all day files. The
// chain.log defines the order; the JSONL files hold the records.
func (l *OccurrenceLog) Walk(visit func(Occurrence) error) error {
	// Build id→record index across all day files.
	files, err := jsonlFiles(l.Dir)
	if err != nil {
		return err
	}
	index := make(map[string]Occurrence)
	for _, f := range files {
		if err := scanOccurrences(f, func(o Occurrence) error {
			index[o.ID] = o
			return nil
		}); err != nil {
			return err
		}
	}
	// Walk chain order.
	_, _, err = chain.Walk(l.ChainPath, func(e chain.Entry) error {
		o, ok := index[e.AssertionID]
		if !ok {
			return fmt.Errorf("chain references missing occurrence %s", e.AssertionID)
		}
		return visit(o)
	})
	return err
}

// WalkAll visits every occurrence in file-and-line order regardless of
// chain. Used by verify to detect chain↔file divergence.
func (l *OccurrenceLog) WalkAll(visit func(o Occurrence, file string, line int) error) error {
	files, err := jsonlFiles(l.Dir)
	if err != nil {
		return err
	}
	for _, f := range files {
		line := 0
		if err := scanOccurrences(f, func(o Occurrence) error {
			line++
			return visit(o, f, line)
		}); err != nil {
			return err
		}
	}
	return nil
}

func scanOccurrences(path string, visit func(Occurrence) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4*1024*1024), 16*1024*1024)
	for sc.Scan() {
		var o Occurrence
		if err := json.Unmarshal(sc.Bytes(), &o); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if err := visit(o); err != nil {
			if errors.Is(err, errStopWalk) {
				return err
			}
			return err
		}
	}
	if err := sc.Err(); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func dayFromIngested(ts string) (string, error) {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return "", fmt.Errorf("parse ingested_at: %w", err)
	}
	return t.UTC().Format("2006-01-02"), nil
}

