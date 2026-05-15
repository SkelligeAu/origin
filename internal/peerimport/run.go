package peerimport

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/SkelligeAu/origin/internal/assertion"
	"github.com/SkelligeAu/origin/internal/keys"
	"github.com/SkelligeAu/origin/internal/peers"
	"github.com/SkelligeAu/origin/internal/raw"
	"github.com/SkelligeAu/origin/internal/vocab"
)

// Run is the CLI entry point for `origin import-occurrences`.
func Run(args []string) error {
	var path, peerKeyArg, peerLogID string
	var registerOnly bool
	i := 0
	for i < len(args) {
		a := args[i]
		switch {
		case a == "--peer-key":
			if i+1 >= len(args) {
				return errors.New("--peer-key requires a value")
			}
			peerKeyArg = args[i+1]
			i += 2
		case a == "--peer-log-id":
			if i+1 >= len(args) {
				return errors.New("--peer-log-id requires a value")
			}
			peerLogID = args[i+1]
			i += 2
		case a == "--register-only":
			registerOnly = true
			i++
		case strings.HasPrefix(a, "--"):
			return fmt.Errorf("unknown flag %q", a)
		default:
			if path != "" {
				return fmt.Errorf("unexpected positional %q (path already set to %q)", a, path)
			}
			path = a
			i++
		}
	}
	if path == "" && !registerOnly {
		return errors.New("usage: origin import-occurrences <path> --peer-key <hex|@file> --peer-log-id <log:id>")
	}
	if peerLogID == "" {
		return errors.New("--peer-log-id is required")
	}

	dataDir := "data"
	registry, err := peers.New(dataDir)
	if err != nil {
		return err
	}

	// Resolve peer key: either from --peer-key flag (first import), or
	// from the registry (subsequent imports).
	var peerKey ed25519.PublicKey
	if peerKeyArg != "" {
		peerKey, err = parsePubKey(peerKeyArg)
		if err != nil {
			return fmt.Errorf("--peer-key: %w", err)
		}
	} else {
		peerKey, err = registry.Resolve(peerLogID)
		if err != nil {
			return err
		}
	}
	// Either way, ensure the registry has this key (no-op if already there).
	if err := registry.RegisterIfAbsent(peerLogID, peerKey); err != nil {
		return err
	}
	if registerOnly {
		fmt.Fprintf(os.Stderr, "✓ peer registered: %s\n", peerLogID)
		return nil
	}

	// Local stores + vocab.
	v, err := vocab.LoadLatest("vocab")
	if err != nil {
		return fmt.Errorf("load vocab: %w", err)
	}
	idents, err := assertion.NewIdentityStore(filepath.Join(dataDir, "assertions", "identities"))
	if err != nil {
		return err
	}
	idents.WithVocab(v)

	ring, err := keys.New(filepath.Join(dataDir, "keys"))
	if err != nil {
		return err
	}
	localLogID, err := keys.ResolveLogID(dataDir, ring)
	if err != nil {
		return err
	}
	localOccs, err := assertion.NewOccurrenceLog(
		filepath.Join(dataDir, "assertions", "occurrences", "local"),
		localLogID,
	)
	if err != nil {
		return err
	}
	rawStore, err := raw.New(filepath.Join(dataDir, "raw"))
	if err != nil {
		return err
	}

	im := &Importer{
		DataDir:       dataDir,
		Idents:        idents,
		LocalOccs:     localOccs,
		RawStore:      rawStore,
		Vocab:         v,
		Ring:          ring,
		Registry:      registry,
		LocalAttestor: ring.Attestor("origin@0.1.0"),
	}
	res, err := im.ImportDir(path, peerLogID, peerKey)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "→ peer:           %s\n", peerLogID)
	fmt.Fprintf(os.Stderr, "→ identities:     %d read\n", res.ForeignIdentitiesRead)
	fmt.Fprintf(os.Stderr, "→ occurrences:    %d read\n", res.ForeignOccurrencesRead)
	fmt.Fprintf(os.Stderr, "→ observations:   %d imported as-is\n", res.ObservationsImported)
	fmt.Fprintf(os.Stderr, "→ verifications:  %d rewritten as peer_reports_*\n", res.VerificationsRewritten)
	fmt.Fprintf(os.Stderr, "→ local emits:    %d federated_importer occurrences\n", res.LocalOccurrencesEmitted)
	fmt.Fprintf(os.Stderr, "✓ import complete\n")
	return nil
}

func parsePubKey(s string) (ed25519.PublicKey, error) {
	if strings.HasPrefix(s, "@") {
		b, err := os.ReadFile(s[1:])
		if err != nil {
			return nil, err
		}
		// File may contain hex or raw bytes; try hex first.
		if k, err := tryHex(strings.TrimSpace(string(b))); err == nil {
			return k, nil
		}
		if len(b) == ed25519.PublicKeySize {
			return ed25519.PublicKey(b), nil
		}
		return nil, fmt.Errorf("%s: unrecognised key file format (want 32 raw bytes or 64 hex chars)", s)
	}
	return tryHex(s)
}

func tryHex(s string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key must decode to %d bytes, got %d", ed25519.PublicKeySize, len(b))
	}
	return ed25519.PublicKey(b), nil
}
