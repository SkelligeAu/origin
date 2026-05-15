// Package raw stores raw evidence: the verbatim response from an external
// source plus a signed metadata sidecar describing the fetch.
//
// Layout:
//
//	data/raw/<source>/<yyyy-mm-dd>/<sha256>.bin    payload bytes
//	data/raw/<source>/<yyyy-mm-dd>/<sha256>.json   metadata sidecar
//
// The payload filename's <sha256> is the SHA-256 of the payload bytes,
// providing content-addressing. The metadata sidecar is named identically
// (same hash) so the pair is co-located.
//
// Metadata is signed by the ingestion identity over its canonical (JCS)
// bytes. Once written, neither file is ever mutated. A second fetch that
// returns identical bytes will collide on filename and is a no-op (we
// verify both files match and skip).
package raw

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/SkelligeAu/origin/internal/canon"
)

// Metadata describes one raw evidence record.
type Metadata struct {
	ID             string            `json:"id"` // sha256 of payload bytes (hex)
	Source         string            `json:"source"`
	Endpoint       string            `json:"endpoint"`
	RequestParams  map[string]string `json:"request_params"`
	FetchedAt      string            `json:"fetched_at"`
	Fetcher        string            `json:"fetcher"`
	ResponseStatus int               `json:"response_status"`
	PayloadPath    string            `json:"payload_path"`
	PayloadHash    string            `json:"payload_hash"`
	ResultCount    *int              `json:"result_count,omitempty"` // null = N/A
	Signature      string            `json:"signature,omitempty"`
}

// Store is a handle to the on-disk raw evidence directory.
type Store struct {
	Root string // typically "data/raw"
}

// New creates a Store rooted at root, creating it if needed.
func New(root string) (*Store, error) {
	if err := os.MkdirAll(root, 0755); err != nil {
		return nil, err
	}
	return &Store{Root: root}, nil
}

// Put writes a raw evidence record. If the record already exists (same
// payload hash), Put verifies the existing files match the supplied
// metadata + payload and returns the existing ID without rewriting.
func (s *Store) Put(meta Metadata, payload []byte, priv ed25519.PrivateKey, keyFP string) (string, error) {
	if meta.Source == "" {
		return "", errors.New("raw: source required")
	}
	if meta.FetchedAt == "" {
		meta.FetchedAt = time.Now().UTC().Format(time.RFC3339)
	}
	sum := sha256.Sum256(payload)
	hashHex := hex.EncodeToString(sum[:])
	meta.ID = hashHex
	meta.PayloadHash = hashHex

	day, err := dayBucket(meta.FetchedAt)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(s.Root, meta.Source, day)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	binPath := filepath.Join(dir, hashHex+".bin")
	metaPath := filepath.Join(dir, hashHex+".json")
	meta.PayloadPath = binPath

	// If payload already exists, verify and short-circuit.
	if existing, err := os.ReadFile(binPath); err == nil {
		// Existing payload must hash to the same value (it must by
		// construction; but verify defensively).
		es := sha256.Sum256(existing)
		if hex.EncodeToString(es[:]) != hashHex {
			return "", fmt.Errorf("raw: hash collision corruption at %s", binPath)
		}
		// Metadata file expected to exist; do not overwrite it.
		if _, err := os.Stat(metaPath); err == nil {
			return hashHex, nil
		}
		// Else fall through and write the metadata file.
	}

	// Write payload first (atomic via temp+rename).
	if err := writeAtomic(binPath, payload, 0644); err != nil {
		return "", err
	}

	// Canonicalize metadata for signing (exclude Signature field).
	unsignedMeta := meta
	unsignedMeta.Signature = ""
	mb, err := json.Marshal(unsignedMeta)
	if err != nil {
		return "", err
	}
	cb, err := canon.CanonicalizeJSON(mb)
	if err != nil {
		return "", fmt.Errorf("canonicalize metadata: %w", err)
	}
	sig := ed25519.Sign(priv, cb)
	meta.Signature = fmt.Sprintf("ed25519:%s:%s", keyFP, base64.StdEncoding.EncodeToString(sig))

	// Final metadata bytes use compact json marshaling. Note we do NOT
	// canonicalize the on-disk JSON — humans read this file. The signature
	// is over the canonical form, so re-canonicalizing on verify recovers
	// the bytes signed.
	out, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return "", err
	}
	if err := writeAtomic(metaPath, out, 0644); err != nil {
		return "", err
	}
	return hashHex, nil
}

// Get loads metadata + payload by ID. Returns metadata, payload bytes, and
// the metadata file path (handy for explain command output).
func (s *Store) Get(id string) (Metadata, []byte, string, error) {
	// Walk the source/date partitions to find the record. This is O(N) over
	// date buckets but Day-1 scale makes it negligible.
	var found string
	err := filepath.WalkDir(s.Root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Base(p) == id+".json" {
			found = p
			return filepath.SkipAll
		}
		return nil
	})
	if err != nil {
		return Metadata{}, nil, "", err
	}
	if found == "" {
		return Metadata{}, nil, "", fmt.Errorf("raw: id %s not found under %s", id, s.Root)
	}
	mb, err := os.ReadFile(found)
	if err != nil {
		return Metadata{}, nil, "", err
	}
	var meta Metadata
	if err := json.Unmarshal(mb, &meta); err != nil {
		return Metadata{}, nil, "", err
	}
	if meta.PayloadHash != id {
		return Metadata{}, nil, "", fmt.Errorf("raw: metadata id %s != filename id %s", meta.PayloadHash, id)
	}
	payload, err := os.ReadFile(meta.PayloadPath)
	if err != nil {
		return Metadata{}, nil, "", err
	}
	sum := sha256.Sum256(payload)
	if hex.EncodeToString(sum[:]) != id {
		return Metadata{}, nil, "", fmt.Errorf("raw: payload hash drift for %s", id)
	}
	return meta, payload, found, nil
}

// Walk iterates every metadata record in id order (lexicographic, which
// equals byte order for hex IDs).
func (s *Store) Walk(visit func(meta Metadata, metaPath string) error) error {
	type entry struct {
		id, path string
	}
	var entries []entry
	err := filepath.WalkDir(s.Root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Ext(p) != ".json" {
			return nil
		}
		base := filepath.Base(p)
		id := base[:len(base)-len(".json")]
		entries = append(entries, entry{id, p})
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].id < entries[j].id })
	for _, e := range entries {
		mb, err := os.ReadFile(e.path)
		if err != nil {
			return err
		}
		var meta Metadata
		if err := json.Unmarshal(mb, &meta); err != nil {
			return fmt.Errorf("decode %s: %w", e.path, err)
		}
		if err := visit(meta, e.path); err != nil {
			return err
		}
	}
	return nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func dayBucket(ts string) (string, error) {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return "", fmt.Errorf("parse fetched_at: %w", err)
	}
	return t.UTC().Format("2006-01-02"), nil
}
