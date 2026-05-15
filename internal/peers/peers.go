// Package peers manages the local registry of federated peer public keys.
//
// One file per peer at data/peers/<peer-log-id>.pub, containing the raw
// 32-byte Ed25519 public key. On first import with --peer-key the key is
// stored; subsequent imports for the same peer-log-id must match or are
// refused.
//
// The registry is also consulted by `origin verify` to check foreign
// occurrence signatures (verify check #11).
//
// Per layer-3.5.md §10 there is no automatic peer discovery, no peer
// reputation, no transitive trust. Every entry in this registry got there
// by an operator's explicit --peer-key invocation.
package peers

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Registry handles peer pubkey storage and lookup under <dataDir>/peers/.
type Registry struct {
	Dir string
}

// New returns a handle; creates the directory if needed.
func New(dataDir string) (*Registry, error) {
	dir := filepath.Join(dataDir, "peers")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	return &Registry{Dir: dir}, nil
}

// Resolve returns the public key for peerLogID, or an error if not
// registered.
func (r *Registry) Resolve(peerLogID string) (ed25519.PublicKey, error) {
	path := r.pathFor(peerLogID)
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("peer %q not registered; supply --peer-key on first import", peerLogID)
		}
		return nil, err
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("peer %q key file has wrong length %d (want %d)", peerLogID, len(b), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

// RegisterIfAbsent stores the public key for peerLogID, refusing if a
// different key is already registered.
func (r *Registry) RegisterIfAbsent(peerLogID string, pub ed25519.PublicKey) error {
	if peerLogID == "" {
		return errors.New("peer_log_id is required")
	}
	if !strings.HasPrefix(peerLogID, "log:") {
		return fmt.Errorf("peer_log_id must start with 'log:' (got %q)", peerLogID)
	}
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	path := r.pathFor(peerLogID)
	existing, err := os.ReadFile(path)
	if err == nil {
		if string(existing) != string(pub) {
			return fmt.Errorf("peer %q already registered with a different key; refusing to overwrite", peerLogID)
		}
		return nil
	}
	if !os.IsNotExist(err) {
		return err
	}
	return os.WriteFile(path, pub, 0644)
}

// List returns all registered peer-log-ids.
func (r *Registry) List() ([]string, error) {
	entries, err := os.ReadDir(r.Dir)
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
		name := e.Name()
		if !strings.HasSuffix(name, ".pub") {
			continue
		}
		out = append(out, name[:len(name)-len(".pub")])
	}
	return out, nil
}

// pathFor maps a peer-log-id to its on-disk pubkey path. The log_id
// itself may contain ":" (e.g. "log:abc123"); we encode that to "_" so
// the filename is shell-friendly. The reverse mapping is lossless because
// only "log:<hex>" form is permitted.
func (r *Registry) pathFor(peerLogID string) string {
	safe := strings.ReplaceAll(peerLogID, ":", "_")
	return filepath.Join(r.Dir, safe+".pub")
}
