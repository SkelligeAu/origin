// Package vocab loads and validates the on-disk predicate vocabulary.
//
// Day-1 risk #5 (vocab file is not the runtime source of truth) closes
// here: every assertion's `predicate` field must match a key in the
// loaded vocabulary or the write is refused.
//
// The vocabulary file is content-addressed (sha256 of the file bytes).
// The hash appears in MANIFEST.json and in every TrustClaim, so changing
// the vocab is a visible, attributable act.
package vocab

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Vocabulary is the parsed vocabulary document.
type Vocabulary struct {
	Version    string                       `json:"version"`
	Supersedes string                       `json:"supersedes,omitempty"`
	Predicates map[string]PredicateDef      `json:"predicates"`

	// computed fields:
	Hash string `json:"-"` // sha256 of the source bytes, hex
	Path string `json:"-"`
}

// PredicateDef describes one predicate.
type PredicateDef struct {
	SubjectKind       string `json:"subject_kind"`
	ObjectKind        string `json:"object_kind"`
	ObjectDatatype    string `json:"object_datatype,omitempty"`
	VerificationClass string `json:"verification_class,omitempty"`
	Description       string `json:"description"`
}

// VerificationClass returns the predicate's verification class
// ("observation", "verification", "refutation", "structural"). Empty
// string if the predicate is not in the loaded vocabulary OR the field
// is unset (pre-v4 vocabs).
func (v *Vocabulary) VerificationClass(predicate string) string {
	if d, ok := v.Predicates[predicate]; ok {
		return d.VerificationClass
	}
	return ""
}

// Load reads vocab/<version>.json, parses it, and returns a Vocabulary
// whose `Hash` field is the sha256 of the source bytes.
func Load(dir, version string) (*Vocabulary, error) {
	path := filepath.Join(dir, version+".json")
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read vocab %s: %w", path, err)
	}
	var v Vocabulary
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("parse vocab %s: %w", path, err)
	}
	if v.Version != version {
		return nil, fmt.Errorf("vocab %s declares version %q, want %q", path, v.Version, version)
	}
	h := sha256.Sum256(b)
	v.Hash = hex.EncodeToString(h[:])
	v.Path = path
	return &v, nil
}

// LoadLatest finds the highest-versioned vocab/<vN>.json under dir and
// returns it. Versions are lexicographic by suffix after "v" (so v2 > v1
// and v10 > v9 because the directory naming uses unpadded integers).
//
// Day-1 had a single version (v1); after Phase 2 we have both. The
// "latest" policy is chosen as the active vocab; older versions remain
// loadable for replaying historical assertions.
func LoadLatest(dir string) (*Vocabulary, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var versions []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !endsWithSuffix(name, ".json") {
			continue
		}
		v := name[:len(name)-len(".json")]
		if len(v) >= 2 && v[0] == 'v' {
			versions = append(versions, v)
		}
	}
	if len(versions) == 0 {
		return nil, fmt.Errorf("no vocab files under %s", dir)
	}
	sort.Slice(versions, func(i, j int) bool { return versionLess(versions[i], versions[j]) })
	return Load(dir, versions[len(versions)-1])
}

// Has returns true if the given predicate name is declared in the vocab.
func (v *Vocabulary) Has(predicate string) bool {
	_, ok := v.Predicates[predicate]
	return ok
}

// PredicateNames returns the predicate names sorted lexicographically.
func (v *Vocabulary) PredicateNames() []string {
	out := make([]string, 0, len(v.Predicates))
	for name := range v.Predicates {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func endsWithSuffix(s, suf string) bool {
	return len(s) >= len(suf) && s[len(s)-len(suf):] == suf
}

// versionLess compares "v1" < "v2" < "v10". Strips the leading "v" and
// compares the trailing integer numerically.
func versionLess(a, b string) bool {
	ai, ae := parseIntAfterV(a)
	bi, be := parseIntAfterV(b)
	if ae == nil && be == nil {
		return ai < bi
	}
	return a < b // fallback lex
}

func parseIntAfterV(s string) (int, error) {
	if len(s) < 2 || s[0] != 'v' {
		return 0, fmt.Errorf("not a vN tag: %q", s)
	}
	n := 0
	for _, c := range s[1:] {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("not numeric: %q", s)
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}
