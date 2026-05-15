// Package anchor implements `origin record-anchor`.
//
// `origin record-anchor <checkpoint-iri> <provider-entry-iri>
//                       --evidence <path-to-provider-response>`
//
// Reads bytes the operator already fetched from a transparency system,
// stores them as raw evidence, and emits a
// `transparency_log_records_checkpoint` identity citing the checkpoint
// and the provider entry. Phase 5 ships no network code; the operator
// handles submission out-of-band.
//
// The predicate is OBSERVATION class. Recording an anchor produces an
// observer-role occurrence by the local key. No verification claim is
// made. See memory/layer-5.md §5.
package anchor

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fitzee/origin/internal/assertion"
	"github.com/fitzee/origin/internal/keys"
	"github.com/fitzee/origin/internal/raw"
	"github.com/fitzee/origin/internal/vocab"
)

const (
	toolVersion           = "origin@0.1.0"
	anchorNormalizer      = "transparency-anchor-recorder@v0.1.0"
	anchorPredicate       = "transparency_log_records_checkpoint"
)

// Run is the CLI entry point.
func Run(args []string) error {
	var checkpointIRI, providerIRI, evidencePath string
	pos := 0
	i := 0
	for i < len(args) {
		a := args[i]
		switch {
		case a == "--evidence":
			if i+1 >= len(args) {
				return errors.New("--evidence requires a value")
			}
			evidencePath = args[i+1]
			i += 2
		case strings.HasPrefix(a, "--"):
			return fmt.Errorf("unknown flag %q", a)
		default:
			switch pos {
			case 0:
				checkpointIRI = a
			case 1:
				providerIRI = a
			default:
				return fmt.Errorf("unexpected positional %q", a)
			}
			pos++
			i++
		}
	}
	if checkpointIRI == "" || providerIRI == "" || evidencePath == "" {
		return errors.New("usage: origin record-anchor <checkpoint:iri> <provider:entry-iri> --evidence <path>")
	}
	if !strings.HasPrefix(checkpointIRI, "checkpoint:") {
		return fmt.Errorf("checkpoint IRI must start with 'checkpoint:', got %q", checkpointIRI)
	}

	dataDir := "data"

	// Confirm the checkpoint IRI resolves to an actual raw evidence record
	// in the local store. This catches typos and orphan-anchor attempts at
	// record time rather than at verify time.
	checkpointHash := strings.TrimPrefix(checkpointIRI, "checkpoint:")
	if len(checkpointHash) != 64 {
		return fmt.Errorf("checkpoint hash must be 64 hex chars (got %d)", len(checkpointHash))
	}
	store, err := raw.New(filepath.Join(dataDir, "raw"))
	if err != nil {
		return err
	}
	if _, _, _, err := store.Get(checkpointHash); err != nil {
		return fmt.Errorf("checkpoint %s not found in raw evidence store: %w", checkpointIRI, err)
	}

	// Read the provider response bytes from --evidence.
	evidenceBytes, err := os.ReadFile(evidencePath)
	if err != nil {
		return fmt.Errorf("read evidence file: %w", err)
	}

	// Derive a raw source name from the provider IRI prefix.
	source := providerSource(providerIRI)

	ring, err := keys.New(filepath.Join(dataDir, "keys"))
	if err != nil {
		return err
	}
	priv, fp := ring.Signer()
	now := time.Now().UTC().Format(time.RFC3339)
	evidenceID, err := store.Put(raw.Metadata{
		Source:   source,
		Endpoint: providerIRI,
		RequestParams: map[string]string{
			"checkpoint": checkpointIRI,
			"provider":   providerIRI,
		},
		FetchedAt:      now,
		Fetcher:        ring.Attestor(toolVersion),
		ResponseStatus: 200,
	}, evidenceBytes, priv, fp)
	if err != nil {
		return fmt.Errorf("store anchor evidence: %w", err)
	}

	// Load vocab + identity store + local occurrence log.
	v, err := vocab.LoadLatest("vocab")
	if err != nil {
		return fmt.Errorf("load vocab: %w", err)
	}
	idents, err := assertion.NewIdentityStore(filepath.Join(dataDir, "assertions", "identities"))
	if err != nil {
		return err
	}
	idents.WithVocab(v)
	logID, err := keys.ResolveLogID(dataDir, ring)
	if err != nil {
		return err
	}
	localOccs, err := assertion.NewOccurrenceLog(
		filepath.Join(dataDir, "assertions", "occurrences", "local"), logID)
	if err != nil {
		return err
	}

	// Emit the anchor identity (observation class).
	id := assertion.Identity{
		Subject:    checkpointIRI,
		Predicate:  anchorPredicate,
		Object:     assertion.Object{Kind: assertion.ObjectIRI, IRI: providerIRI},
		EvidenceID: evidenceID,
		ObservedAt: now,
		Normalizer: anchorNormalizer,
		Vocab:      v.Version,
	}
	stored, err := idents.Put(id)
	if err != nil {
		return fmt.Errorf("store anchor identity: %w", err)
	}

	// Emit an observer-role occurrence (anchor predicate is observation
	// class; the role check passes by vocab class).
	_, err = localOccs.Append(stored.ID, ring.Attestor(toolVersion),
		assertion.RoleObserver, priv, fp)
	if err != nil {
		return fmt.Errorf("append anchor occurrence: %w", err)
	}

	// Hash the evidence file for display purposes.
	evHash := sha256.Sum256(evidenceBytes)
	fmt.Fprintf(os.Stderr, "→ checkpoint:       %s\n", checkpointIRI)
	fmt.Fprintf(os.Stderr, "→ provider entry:   %s\n", providerIRI)
	fmt.Fprintf(os.Stderr, "→ evidence:         %s  (%d bytes, sha256=%s…)\n",
		source, len(evidenceBytes), hex.EncodeToString(evHash[:8]))
	fmt.Fprintf(os.Stderr, "→ identity:         %s\n", stored.ID)
	fmt.Fprintf(os.Stderr, "✓ anchor recorded as %s (observation class)\n", anchorPredicate)
	return nil
}

// providerSource derives a raw-evidence source name from a provider IRI.
// Conventions:
//   rekor:42:abc123    → "sigstore.rekor.anchor"
//   fakelog:fixture:1  → "fakelog.anchor"
//   git:<commit-sha>   → "git.anchor"
// Unknown prefixes fall back to "<prefix>.anchor".
func providerSource(iri string) string {
	idx := strings.IndexByte(iri, ':')
	if idx < 0 {
		return "unknown.anchor"
	}
	prefix := iri[:idx]
	switch prefix {
	case "rekor":
		return "sigstore.rekor.anchor"
	default:
		return prefix + ".anchor"
	}
}
