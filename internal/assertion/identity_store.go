package assertion

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// IdentityStore is the append-only, content-addressed Identity log under
// data/assertions/identities/. Writes are idempotent: storing an identity
// whose ID already exists is a no-op (the identity is the same fact, by
// definition).
type IdentityStore struct {
	Dir   string
	Vocab PredicateChecker
}

// PredicateChecker validates that a predicate name is declared in the
// active vocabulary. internal/vocab.Vocabulary satisfies this naturally.
type PredicateChecker interface {
	Has(predicate string) bool
}

// NewIdentityStore returns a handle, creating the directory if needed.
func NewIdentityStore(dir string) (*IdentityStore, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	return &IdentityStore{Dir: dir}, nil
}

// WithVocab attaches a predicate-vocabulary check that fires at append
// time. Predicates not declared in the active vocabulary are refused.
func (s *IdentityStore) WithVocab(v PredicateChecker) *IdentityStore {
	s.Vocab = v
	return s
}

// Put writes an identity to the store. ID is computed from the envelope;
// if an identity with the same ID already exists, Put is a no-op and
// returns the existing record. Returns the persisted Identity (with its
// ID populated).
func (s *IdentityStore) Put(i Identity) (Identity, error) {
	if err := i.Validate(); err != nil {
		return Identity{}, err
	}
	if s.Vocab != nil && !s.Vocab.Has(i.Predicate) {
		return Identity{}, fmt.Errorf("predicate %q not declared in active vocabulary", i.Predicate)
	}
	id, err := i.ComputeID()
	if err != nil {
		return Identity{}, err
	}
	i.ID = id

	if existing, ok, err := s.Find(id); err != nil {
		return Identity{}, err
	} else if ok {
		return existing, nil
	}

	day := time.Now().UTC().Format("2006-01-02")
	path := filepath.Join(s.Dir, day+".jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return Identity{}, err
	}
	defer f.Close()
	b, err := json.Marshal(i)
	if err != nil {
		return Identity{}, err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		return Identity{}, err
	}
	return i, nil
}

// Find returns the identity with this ID, or (Identity{}, false, nil) if
// not present.
func (s *IdentityStore) Find(id string) (Identity, bool, error) {
	var found Identity
	var ok bool
	err := s.Walk(func(i Identity) error {
		if i.ID == id {
			found = i
			ok = true
			return errStopWalk
		}
		return nil
	})
	if errors.Is(err, errStopWalk) {
		return found, true, nil
	}
	if err != nil {
		return Identity{}, false, err
	}
	return Identity{}, ok, nil
}

// Walk visits every identity in lexicographic file order. Visit may
// return errStopWalk to terminate early.
func (s *IdentityStore) Walk(visit func(Identity) error) error {
	files, err := jsonlFiles(s.Dir)
	if err != nil {
		return err
	}
	for _, f := range files {
		if err := scanIdentities(f, visit); err != nil {
			return err
		}
	}
	return nil
}

var errStopWalk = errors.New("stop walk")

func scanIdentities(path string, visit func(Identity) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4*1024*1024), 16*1024*1024)
	for sc.Scan() {
		var i Identity
		if err := json.Unmarshal(sc.Bytes(), &i); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if err := visit(i); err != nil {
			if errors.Is(err, errStopWalk) {
				return err
			}
			return err
		}
	}
	if err := sc.Err(); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func jsonlFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
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
		if !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		out = append(out, filepath.Join(dir, e.Name()))
	}
	sort.Strings(out)
	return out, nil
}
