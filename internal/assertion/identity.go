package assertion

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/fitzee/origin/internal/canon"
)

// Identity is the canonical content-addressable fact. An identity carries
// NO information about who recorded it, when, or in which log: those
// belong to the Occurrence. Two ingestors observing the same source bytes
// through the same normalizer produce the same Identity bytes and
// therefore the same identity_id.
//
// Fields are exactly those that participate in fact identity (§2.1 of
// memory/layer-3.md). Adding a field to this type requires a vocabulary
// version bump.
type Identity struct {
	ID         string  `json:"id"` // sha256 of canonical envelope below
	Subject    string  `json:"subject"`
	Predicate  string  `json:"predicate"`
	Object     Object  `json:"object"`
	EvidenceID string  `json:"evidence_id"`
	ObservedAt string  `json:"observed_at"`
	Normalizer string  `json:"normalizer"`
	Vocab      string  `json:"vocab"`
	Revises    *string `json:"revises"`
}

// identityEnvelopeJSON is the field set whose canonical bytes are hashed
// to produce identity_id. ID is excluded.
type identityEnvelopeJSON struct {
	Subject    string  `json:"subject"`
	Predicate  string  `json:"predicate"`
	Object     Object  `json:"object"`
	EvidenceID string  `json:"evidence_id"`
	ObservedAt string  `json:"observed_at"`
	Normalizer string  `json:"normalizer"`
	Vocab      string  `json:"vocab"`
	Revises    *string `json:"revises"`
}

// Validate enforces structural completeness of an Identity envelope.
// Missing required fields → reject at write time (epistemic-model.v1.md
// invariant 5 applied at the identity layer).
func (i Identity) Validate() error {
	if i.Subject == "" {
		return errors.New("subject is required")
	}
	if i.Predicate == "" {
		return errors.New("predicate is required")
	}
	if err := i.Object.Validate(); err != nil {
		return fmt.Errorf("object: %w", err)
	}
	if i.EvidenceID == "" {
		return errors.New("evidence_id is required")
	}
	if _, err := time.Parse(time.RFC3339, i.ObservedAt); err != nil {
		return fmt.Errorf("observed_at: %w", err)
	}
	if i.Normalizer == "" {
		return errors.New("normalizer is required")
	}
	if i.Vocab == "" {
		return errors.New("vocab is required")
	}
	return nil
}

// CanonicalBytes returns the JCS canonical encoding of the envelope
// fields. ID is excluded; this is what its hash signs.
func (i Identity) CanonicalBytes() ([]byte, error) {
	if err := i.Validate(); err != nil {
		return nil, err
	}
	env := identityEnvelopeJSON{
		Subject:    i.Subject,
		Predicate:  i.Predicate,
		Object:     i.Object,
		EvidenceID: i.EvidenceID,
		ObservedAt: i.ObservedAt,
		Normalizer: i.Normalizer,
		Vocab:      i.Vocab,
		Revises:    i.Revises,
	}
	b, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	return canon.CanonicalizeJSON(b)
}

// ComputeID returns sha256(canonical envelope) as lowercase hex.
func (i Identity) ComputeID() (string, error) {
	cb, err := i.CanonicalBytes()
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(cb)
	return hex.EncodeToString(h[:]), nil
}

// VerifyID confirms the stored ID equals the recomputed canonical hash.
func (i Identity) VerifyID() error {
	want, err := i.ComputeID()
	if err != nil {
		return err
	}
	if want != i.ID {
		return fmt.Errorf("identity id mismatch: want %s, got %s", want, i.ID)
	}
	return nil
}
