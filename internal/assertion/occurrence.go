package assertion

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/SkelligeAu/origin/internal/canon"
)

// AttestorRole discriminates how an ingestor came to record an Identity.
// The role is part of the canonical occurrence envelope, so two
// occurrences for the same Identity with different roles are distinct
// records.
//
// Roles:
//   - RoleObserver: the ingestor's normalizer recorded a parse of source
//     bytes (the standard observation path).
//   - RoleVerifier: the ingestor's verifier code executed a cryptographic
//     procedure and produced this identity locally. Only verifier-role
//     occurrences may name verified-form predicates (invariant 16).
//   - RoleFederatedImporter: the ingestor accepted this identity from
//     another log. Federated-importer-role occurrences may NOT name
//     verified-form predicates; at the federation boundary verified-form
//     identities are rewritten as peer_reports_* observation predicates.
type AttestorRole string

const (
	RoleObserver          AttestorRole = "observer"
	RoleVerifier          AttestorRole = "verifier"
	RoleFederatedImporter AttestorRole = "federated_importer"
)

// Occurrence is the local ingestion event: this log saw this identity
// at this time, signed by this attestor, in this chain position. The
// occurrence envelope is itself content-addressed; its ID is distinct
// from the identity it names.
type Occurrence struct {
	ID            string       `json:"id"`
	IdentityID    string       `json:"identity_id"`
	Attestor      string       `json:"attestor"`
	AttestorRole  AttestorRole `json:"attestor_role"`
	IngestedAt    string       `json:"ingested_at"`
	LogID         string       `json:"log_id"`
	PrevChainHash string       `json:"prev_chain_hash"`
	ChainHash     string       `json:"chain_hash"`
	Signature     string       `json:"signature"`
}

// occurrenceEnvelopeJSON is the canonical content of an occurrence whose
// hash is the occurrence ID. ID, ChainHash, and Signature are excluded:
//   - ID is the hash, can't include itself.
//   - ChainHash depends on log position (set at append time).
//   - Signature signs the canonical envelope.
type occurrenceEnvelopeJSON struct {
	IdentityID    string       `json:"identity_id"`
	Attestor      string       `json:"attestor"`
	AttestorRole  AttestorRole `json:"attestor_role"`
	IngestedAt    string       `json:"ingested_at"`
	LogID         string       `json:"log_id"`
	PrevChainHash string       `json:"prev_chain_hash"`
}

// Validate enforces structural completeness of an Occurrence envelope.
func (o Occurrence) Validate() error {
	if o.IdentityID == "" {
		return errors.New("identity_id is required")
	}
	if len(o.IdentityID) != 64 {
		return fmt.Errorf("identity_id must be 64 hex chars, got %d", len(o.IdentityID))
	}
	if o.Attestor == "" {
		return errors.New("attestor is required")
	}
	switch o.AttestorRole {
	case RoleObserver, RoleVerifier, RoleFederatedImporter:
		// valid
	default:
		return fmt.Errorf("attestor_role must be one of {observer, verifier, federated_importer}, got %q", o.AttestorRole)
	}
	if _, err := time.Parse(time.RFC3339, o.IngestedAt); err != nil {
		return fmt.Errorf("ingested_at: %w", err)
	}
	if o.LogID == "" {
		return errors.New("log_id is required")
	}
	if o.PrevChainHash == "" {
		return errors.New("prev_chain_hash is required (use chain.Genesis for the first occurrence)")
	}
	return nil
}

// CanonicalBytes returns the JCS canonical encoding of the occurrence
// envelope fields. This is what the occurrence ID hashes AND what the
// signature signs.
func (o Occurrence) CanonicalBytes() ([]byte, error) {
	if err := o.Validate(); err != nil {
		return nil, err
	}
	env := occurrenceEnvelopeJSON{
		IdentityID:    o.IdentityID,
		Attestor:      o.Attestor,
		AttestorRole:  o.AttestorRole,
		IngestedAt:    o.IngestedAt,
		LogID:         o.LogID,
		PrevChainHash: o.PrevChainHash,
	}
	b, err := json.Marshal(env)
	if err != nil {
		return nil, err
	}
	return canon.CanonicalizeJSON(b)
}

// ComputeID returns sha256(canonical envelope) as lowercase hex.
func (o Occurrence) ComputeID() (string, error) {
	cb, err := o.CanonicalBytes()
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(cb)
	return hex.EncodeToString(h[:]), nil
}

// Sign produces an Ed25519 signature over the canonical envelope.
func (o Occurrence) Sign(priv ed25519.PrivateKey, keyFP string) (string, error) {
	cb, err := o.CanonicalBytes()
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, cb)
	return fmt.Sprintf("ed25519:%s:%s", keyFP, base64.StdEncoding.EncodeToString(sig)), nil
}

// VerifySignature checks o.Signature is valid for the canonical envelope.
func (o Occurrence) VerifySignature(keyResolver func(fp string) (ed25519.PublicKey, error)) error {
	algo, fp, sigB64, ok := splitSig(o.Signature)
	if !ok {
		return fmt.Errorf("malformed signature %q", o.Signature)
	}
	if algo != "ed25519" {
		return fmt.Errorf("unsupported signature algorithm %q", algo)
	}
	pub, err := keyResolver(fp)
	if err != nil {
		return fmt.Errorf("resolve key %q: %w", fp, err)
	}
	cb, err := o.CanonicalBytes()
	if err != nil {
		return fmt.Errorf("canonical bytes: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(pub, cb, sig) {
		return errors.New("occurrence signature does not verify")
	}
	return nil
}

// VerifyID confirms the stored ID equals the recomputed canonical hash.
func (o Occurrence) VerifyID() error {
	want, err := o.ComputeID()
	if err != nil {
		return err
	}
	if want != o.ID {
		return fmt.Errorf("occurrence id mismatch: want %s, got %s", want, o.ID)
	}
	return nil
}

// ComputeChainHash returns the next chain hash given a prev hash and an
// occurrence id. The formula incorporates the occurrence id (which itself
// carries the attestor and identity), so two ingestors writing the same
// identity diverge at the chain level.
//
// Concretely: chain_hash = sha256(prev_chain_hash || occurrence_id), both
// inputs as raw 32-byte values.
func ComputeOccurrenceChainHash(prevChainHashHex, occurrenceIDHex string) (string, error) {
	prev, err := hex.DecodeString(prevChainHashHex)
	if err != nil || len(prev) != 32 {
		return "", fmt.Errorf("invalid prev_chain_hash %q", prevChainHashHex)
	}
	oid, err := hex.DecodeString(occurrenceIDHex)
	if err != nil || len(oid) != 32 {
		return "", fmt.Errorf("invalid occurrence id %q", occurrenceIDHex)
	}
	h := sha256.New()
	h.Write(prev)
	h.Write(oid)
	return hex.EncodeToString(h.Sum(nil)), nil
}
