package ingest

import (
	"crypto/ed25519"
	"fmt"

	"github.com/fitzee/origin/internal/assertion"
	"github.com/fitzee/origin/internal/vocab"
)

// emitter wires the IdentityStore + OccurrenceLog + signing key into a
// single record-an-identity-and-its-occurrence operation. The role is
// determined by the predicate's verification_class in the active vocab:
//   observation  → observer
//   structural   → observer  (structural meta-predicates are not produced
//                             by verifiers; treat as observer)
//   verification → verifier
//   refutation   → verifier
//
// Federation imports are not handled here; they'll arrive via a separate
// path in Phase 3.5 carrying RoleFederatedImporter explicitly.
type emitter struct {
	idents *assertion.IdentityStore
	occs   *assertion.OccurrenceLog
	priv   ed25519.PrivateKey
	fp     string
	attestor string
	vocab  *vocab.Vocabulary
}

func newEmitter(
	idents *assertion.IdentityStore, occs *assertion.OccurrenceLog,
	priv ed25519.PrivateKey, fp, attestor string,
	v *vocab.Vocabulary,
) *emitter {
	return &emitter{idents: idents, occs: occs, priv: priv, fp: fp, attestor: attestor, vocab: v}
}

func (e *emitter) emit(id assertion.Identity) (assertion.Identity, assertion.Occurrence, error) {
	role, err := e.roleFor(id.Predicate)
	if err != nil {
		return assertion.Identity{}, assertion.Occurrence{}, err
	}
	stored, err := e.idents.Put(id)
	if err != nil {
		return assertion.Identity{}, assertion.Occurrence{}, fmt.Errorf("put identity %s: %w", id.Predicate, err)
	}
	occ, err := e.occs.Append(stored.ID, e.attestor, role, e.priv, e.fp)
	if err != nil {
		return assertion.Identity{}, assertion.Occurrence{}, fmt.Errorf("append occurrence: %w", err)
	}
	return stored, occ, nil
}

// roleFor maps a predicate to the attestor role its emitter must use.
// Refuses if the vocab does not declare the predicate or omits the
// verification_class field (pre-v4 vocabs).
func (e *emitter) roleFor(predicate string) (assertion.AttestorRole, error) {
	class := e.vocab.VerificationClass(predicate)
	switch class {
	case "observation", "structural":
		return assertion.RoleObserver, nil
	case "verification", "refutation":
		return assertion.RoleVerifier, nil
	case "":
		return "", fmt.Errorf("predicate %q has no verification_class declared in vocab %s", predicate, e.vocab.Version)
	default:
		return "", fmt.Errorf("predicate %q has unknown verification_class %q", predicate, class)
	}
}
