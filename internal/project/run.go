package project

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fitzee/origin/internal/assertion"
	"github.com/fitzee/origin/internal/keys"
	"github.com/fitzee/origin/internal/raw"
)

func runProject(args []string) error {
	dataDir := "data"
	rawStore, err := raw.New(filepath.Join(dataDir, "raw"))
	if err != nil {
		return err
	}
	idents, err := assertion.NewIdentityStore(filepath.Join(dataDir, "assertions", "identities"))
	if err != nil {
		return err
	}
	ring, err := keys.New(filepath.Join(dataDir, "keys"))
	if err != nil {
		return err
	}
	logID, err := keys.ResolveLogID(dataDir, ring)
	if err != nil {
		return fmt.Errorf("resolve log id: %w", err)
	}
	occs, err := assertion.NewOccurrenceLog(filepath.Join(dataDir, "assertions", "occurrences", "local"), logID)
	if err != nil {
		return err
	}
	foreignOccs, err := DiscoverForeignOccurrenceLogs(dataDir)
	if err != nil {
		return fmt.Errorf("discover foreign logs: %w", err)
	}
	p := New(filepath.Join(dataDir, "projections"))
	if err := p.Build(idents, occs, foreignOccs, rawStore); err != nil {
		return err
	}
	manifest, err := os.ReadFile(p.ManifestPath)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "✓ projection built\n%s\n", manifest)
	return nil
}

// DiscoverForeignOccurrenceLogs returns an OccurrenceLog handle for every
// subdirectory under data/assertions/occurrences/foreign/. The peer_log_id
// is reconstructed from the directory name (":" was replaced with "_"
// in filenameSafe; we reverse).
func DiscoverForeignOccurrenceLogs(dataDir string) ([]*assertion.OccurrenceLog, error) {
	foreignDir := filepath.Join(dataDir, "assertions", "occurrences", "foreign")
	entries, err := os.ReadDir(foreignDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []*assertion.OccurrenceLog
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		peerLogID := strings.Replace(e.Name(), "_", ":", 1)
		log, err := assertion.NewOccurrenceLog(filepath.Join(foreignDir, e.Name()), peerLogID)
		if err != nil {
			return nil, err
		}
		out = append(out, log)
	}
	return out, nil
}
