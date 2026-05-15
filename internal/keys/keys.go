// Package keys manages the local Ed25519 signing key used by the
// ingestion identity.
//
// Day-1 scope:
//   - One key on disk at data/keys/ingestor.ed25519 (32 bytes, raw).
//   - The public key fingerprint is sha256(public-key-bytes), hex,
//     truncated to 16 chars for ergonomic display.
//   - If the key file does not exist, it is generated on first use.
//
// Phase-2 will add a registry of attestor public keys; Day-1 only needs to
// resolve our own key for verification.
package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const FingerprintLen = 16

// Ring is the local key registry.
type Ring struct {
	mu      sync.RWMutex
	dir     string
	signer  ed25519.PrivateKey
	signFP  string
	known   map[string]ed25519.PublicKey // fp → public
}

// New loads (or creates) the local signing key at <dir>/ingestor.ed25519
// and returns a Ring with that key set as the active signer.
func New(dir string) (*Ring, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "ingestor.ed25519")
	priv, err := loadOrCreate(path)
	if err != nil {
		return nil, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	fp := Fingerprint(pub)
	r := &Ring{
		dir:    dir,
		signer: priv,
		signFP: fp,
		known:  map[string]ed25519.PublicKey{fp: pub},
	}
	// Persist the public key alongside for verification.
	if err := os.WriteFile(filepath.Join(dir, "ingestor.pub"), pub, 0644); err != nil {
		return nil, err
	}
	return r, nil
}

// Signer returns the active signing key and its fingerprint.
func (r *Ring) Signer() (ed25519.PrivateKey, string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.signer, r.signFP
}

// Resolve returns the public key for fp, or an error if unknown.
func (r *Ring) Resolve(fp string) (ed25519.PublicKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	pk, ok := r.known[fp]
	if !ok {
		return nil, fmt.Errorf("unknown key fingerprint %q", fp)
	}
	return pk, nil
}

// Fingerprint returns the truncated-hex sha256 of the public key bytes.
func Fingerprint(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return hex.EncodeToString(h[:])[:FingerprintLen]
}

func loadOrCreate(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		if len(b) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("keys: %s has wrong length %d", path, len(b))
		}
		return ed25519.PrivateKey(b), nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, priv, 0600); err != nil {
		return nil, err
	}
	return priv, nil
}

// Attestor returns the canonical attestor identifier we embed in
// occurrences signed by the ingestor.
func (r *Ring) Attestor(toolVersion string) string {
	return fmt.Sprintf("ingestor:%s:%s", toolVersion, r.signFP)
}

// LogID returns the deterministic log identifier for this ring. Phase 3
// derives log_id directly from the signing-key fingerprint: distinct
// keys mean distinct logs. Key rotation creates a new log_id (correct
// behaviour: a different signer is a different attestor and writes a
// different chain).
//
// Operators wanting a non-default log_id can override by placing a file
// at data/log-id.txt; this Ring does not implement that override (it's
// a callsite concern), but ResolveLogID below honours it.
func (r *Ring) LogID() string {
	return "log:" + r.signFP
}

// ResolveLogID returns the log_id for this data directory. If
// <dataDir>/log-id.txt exists and contains a non-empty trimmed value,
// that value is used. Otherwise the default is ring.LogID().
func ResolveLogID(dataDir string, ring *Ring) (string, error) {
	path := fmt.Sprintf("%s/log-id.txt", dataDir)
	b, err := os.ReadFile(path)
	if err == nil {
		s := string(b)
		// trim trailing whitespace/newlines
		for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
			s = s[:len(s)-1]
		}
		if s != "" {
			return s, nil
		}
	}
	if !os.IsNotExist(err) && err != nil {
		return "", err
	}
	return ring.LogID(), nil
}

// ErrNoSigner is returned if the active signer is not set.
var ErrNoSigner = errors.New("no active signer")
