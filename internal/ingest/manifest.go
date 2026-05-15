package ingest

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// writeNormalizerManifest persists the set of normalizer versions in use.
// The projection records normalizer versions per-assertion, but the
// manifest acts as an at-a-glance audit of what is currently in code.
func writeNormalizerManifest(dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	type entry struct {
		ID    string `json:"id"`
		About string `json:"about"`
	}
	manifest := struct {
		Vocab       string  `json:"vocab"`
		Normalizers []entry `json:"normalizers"`
	}{
		Vocab: VocabVersion,
		Normalizers: []entry{
			{NormalizerNPM, "npm registry per-version record → assertions"},
			{NormalizerOSV, "OSV /v1/query response → affected_by assertions"},
			{NormalizerRekor, "Sigstore Rekor index/retrieve — Day-1 records lookup only"},
			{NormalizerGH, "GitHub /repos and /contents — recorded as raw evidence only"},
		},
	}
	out, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "manifest.json"), out, 0644)
}
