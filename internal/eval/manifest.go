package eval

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// PolicyManifest mirrors policies/<name>/manifest.json on disk.
type PolicyManifest struct {
	ID                 string            `json:"id"`
	Version            string            `json:"version"`
	VocabRequired      string            `json:"vocab_required"`
	RequiredPredicates []string          `json:"required_predicates"`
	RequiredRawSources []string          `json:"required_raw_sources"`
	NeighborhoodDepth  int               `json:"neighborhood_depth"`
	AllowedVerdicts    []string          `json:"allowed_verdicts"`
	Queries            map[string]string `json:"queries"`

	// Computed fields, not in the on-disk JSON:
	PolicyHash string `json:"-"`
	PolicyRego string `json:"-"`
	Path       string `json:"-"`
}

// LoadPolicy reads a policy by name and version. The name may include a
// version selector: "release_signing" (highest version), or
// "release_signing@v2" (explicit version).
//
// On disk the layout is policies/<name>/<version>/{manifest.json,policy.rego}.
// Versions are vN strings; "highest" means largest integer N.
//
// Why versioned subdirectories: claims signed against a policy hash must
// remain replayable. If we edited a policy in place, the policy hash
// would change and old claims could not be re-derived against current
// code. Frozen v1 + new v2 preserves both.
func LoadPolicy(spec string) (*PolicyManifest, error) {
	name, version := parsePolicySpec(spec)
	versionDir, resolvedVersion, err := resolvePolicyVersion(name, version)
	if err != nil {
		return nil, err
	}
	manB, err := os.ReadFile(filepath.Join(versionDir, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var m PolicyManifest
	if err := json.Unmarshal(manB, &m); err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}
	if m.ID != name {
		return nil, fmt.Errorf("manifest id %q != requested name %q", m.ID, name)
	}
	if m.Version != resolvedVersion {
		return nil, fmt.Errorf("manifest version %q != directory %q", m.Version, resolvedVersion)
	}
	regoB, err := os.ReadFile(filepath.Join(versionDir, "policy.rego"))
	if err != nil {
		return nil, fmt.Errorf("read policy.rego: %w", err)
	}
	for _, v := range m.AllowedVerdicts {
		if !allowedVerdicts[v] {
			return nil, fmt.Errorf("manifest declares disallowed verdict %q", v)
		}
	}
	h := sha256.New()
	h.Write(manB)
	h.Write([]byte{0})
	h.Write(regoB)
	m.PolicyHash = hex.EncodeToString(h.Sum(nil))
	m.PolicyRego = string(regoB)
	m.Path = versionDir
	return &m, nil
}

// parsePolicySpec splits "name" or "name@version" into its parts.
func parsePolicySpec(spec string) (name, version string) {
	for i := 0; i < len(spec); i++ {
		if spec[i] == '@' {
			return spec[:i], spec[i+1:]
		}
	}
	return spec, ""
}

// resolvePolicyVersion returns the directory and version label for the
// requested policy. If version is empty, returns the highest-numbered
// vN subdirectory.
func resolvePolicyVersion(name, version string) (dir, resolved string, err error) {
	base := filepath.Join("policies", name)
	if version != "" {
		dir = filepath.Join(base, version)
		if _, err := os.Stat(dir); err != nil {
			return "", "", fmt.Errorf("policy %s@%s not found at %s", name, version, dir)
		}
		return dir, version, nil
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		return "", "", fmt.Errorf("read policy dir %s: %w", base, err)
	}
	highest := ""
	highestN := -1
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		n, ok := parseVN(e.Name())
		if !ok {
			continue
		}
		if n > highestN {
			highestN = n
			highest = e.Name()
		}
	}
	if highest == "" {
		return "", "", fmt.Errorf("policy %s has no vN subdirectories under %s", name, base)
	}
	return filepath.Join(base, highest), highest, nil
}

func parseVN(s string) (int, bool) {
	if len(s) < 2 || s[0] != 'v' {
		return 0, false
	}
	n := 0
	for _, c := range s[1:] {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}
