package checkpoint

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/SkelligeAu/origin/internal/chain"
	"github.com/SkelligeAu/origin/internal/keys"
	"github.com/SkelligeAu/origin/internal/raw"
)

const toolVersion = "origin@0.1.0"

// Run is the CLI entry point for `origin checkpoint`.
//
//	origin checkpoint [--output <path>]
//
// Reads the current local chain head, constructs a signed Checkpoint,
// stores it as raw evidence, and (optionally) writes a copy to <path>.
// Prints the resulting checkpoint:<hash> IRI to stdout.
func Run(args []string) error {
	var outputPath string
	i := 0
	for i < len(args) {
		a := args[i]
		switch {
		case a == "--output":
			if i+1 >= len(args) {
				return errors.New("--output requires a value")
			}
			outputPath = args[i+1]
			i += 2
		case strings.HasPrefix(a, "--"):
			return fmt.Errorf("unknown flag %q", a)
		default:
			return fmt.Errorf("unexpected positional %q", a)
		}
	}

	dataDir := "data"
	ring, err := keys.New(filepath.Join(dataDir, "keys"))
	if err != nil {
		return err
	}
	logID, err := keys.ResolveLogID(dataDir, ring)
	if err != nil {
		return err
	}
	chainPath := filepath.Join(dataDir, "assertions", "occurrences", "local", "chain.log")
	head, seq, err := chain.Head(chainPath)
	if err != nil {
		return fmt.Errorf("read chain head: %w", err)
	}
	if seq == 0 {
		return errors.New("local chain is empty; nothing to checkpoint")
	}

	env := Envelope{
		LogID:     logID,
		Seq:       seq,
		ChainHash: head,
		SignedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	priv, fp := ring.Signer()
	sig, err := env.Sign(priv, fp)
	if err != nil {
		return err
	}
	signed := Signed{Checkpoint: env, Signature: sig}
	iri, err := signed.IRI()
	if err != nil {
		return err
	}

	// Persist as raw evidence so anchor identities can cite it by hash.
	// The IRI is over the JCS canonical bytes of the signed envelope; the
	// stored bytes MUST also be canonical so the file's content-hash
	// (== filename) equals the hash embedded in the IRI.
	store, err := raw.New(filepath.Join(dataDir, "raw"))
	if err != nil {
		return err
	}
	signedBytes, err := signed.SignedCanonicalBytes()
	if err != nil {
		return err
	}
	if _, err := store.Put(raw.Metadata{
		Source:         "origin.checkpoint",
		Endpoint:       "local:" + logID,
		RequestParams:  map[string]string{"log_id": logID, "seq": fmt.Sprintf("%d", seq)},
		FetchedAt:      env.SignedAt,
		Fetcher:        ring.Attestor(toolVersion),
		ResponseStatus: 200,
	}, signedBytes, priv, fp); err != nil {
		return fmt.Errorf("store checkpoint as raw evidence: %w", err)
	}

	// Optional copy to --output.
	if outputPath != "" {
		if err := os.MkdirAll(filepath.Dir(outputPath), 0755); err != nil {
			return err
		}
		if err := os.WriteFile(outputPath, signedBytes, 0644); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "→ checkpoint written to %s\n", outputPath)
	}

	fmt.Fprintf(os.Stderr, "→ checkpoint  log_id=%s  seq=%d  head=%s…\n", logID, seq, head[:16])
	fmt.Fprintf(os.Stderr, "✓ checkpoint IRI:\n")
	fmt.Println(iri)
	return nil
}
