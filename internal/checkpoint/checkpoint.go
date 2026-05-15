// Package checkpoint implements the signed local-chain checkpoint
// artefact used by Phase-5 transparency anchoring.
//
// A Checkpoint is a small signed document recording the local chain's
// state at one moment:
//
//	{ log_id, seq, chain_hash, signed_at, signature }
//
// It is content-addressable: the IRI used to name a checkpoint in an
// anchor identity is "checkpoint:<sha256-of-canonical-signed-envelope>".
//
// Phase 5 stores checkpoints as raw evidence under
//
//	data/raw/origin.checkpoint/<yyyy-mm-dd>/<sha256>.bin
//
// alongside the rest of the raw evidence store. Anchor identities
// reference checkpoints via their content-hash IRI; no separate
// checkpoint store is needed.
//
// Checkpoints are NOT predicate-bearing identities. They are evidence
// referenced BY anchor identities. See memory/layer-5.md §4.
package checkpoint

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/fitzee/origin/internal/canon"
)

// Envelope is the canonical content of a checkpoint. JCS-canonicalised
// and signed.
type Envelope struct {
	LogID     string `json:"log_id"`
	Seq       uint64 `json:"seq"`
	ChainHash string `json:"chain_hash"`
	SignedAt  string `json:"signed_at"`
}

// Validate enforces structural completeness.
func (e Envelope) Validate() error {
	if e.LogID == "" {
		return errors.New("log_id is required")
	}
	if e.Seq == 0 {
		return errors.New("seq must be > 0 (cannot anchor the empty chain)")
	}
	if len(e.ChainHash) != 64 {
		return fmt.Errorf("chain_hash must be 64 hex chars, got %d", len(e.ChainHash))
	}
	if _, err := time.Parse(time.RFC3339, e.SignedAt); err != nil {
		return fmt.Errorf("signed_at: %w", err)
	}
	return nil
}

// CanonicalBytes returns the JCS canonical encoding of the envelope.
// This is what the signature signs and what the content hash hashes
// (via the Signed wrapper below).
func (e Envelope) CanonicalBytes() ([]byte, error) {
	if err := e.Validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(e)
	if err != nil {
		return nil, err
	}
	return canon.CanonicalizeJSON(b)
}

// Sign produces an Ed25519 signature over the canonical envelope bytes.
func (e Envelope) Sign(priv ed25519.PrivateKey, keyFP string) (string, error) {
	cb, err := e.CanonicalBytes()
	if err != nil {
		return "", err
	}
	sig := ed25519.Sign(priv, cb)
	return fmt.Sprintf("ed25519:%s:%s", keyFP, base64.StdEncoding.EncodeToString(sig)), nil
}

// Signed is the on-disk shape: envelope + signature. The content hash
// (used to form the checkpoint IRI) is sha256 of the canonical bytes of
// this Signed structure.
type Signed struct {
	Checkpoint Envelope `json:"checkpoint"`
	Signature  string   `json:"signature"`
}

// SignedCanonicalBytes returns the JCS canonical encoding of the signed
// envelope. This is what the checkpoint IRI hashes.
func (s Signed) SignedCanonicalBytes() ([]byte, error) {
	if err := s.Checkpoint.Validate(); err != nil {
		return nil, err
	}
	if s.Signature == "" {
		return nil, errors.New("signature is required")
	}
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	return canon.CanonicalizeJSON(b)
}

// ContentHash returns the sha256 (hex) of the signed canonical bytes.
// Used to form the "checkpoint:<hash>" IRI in anchor identities.
func (s Signed) ContentHash() (string, error) {
	cb, err := s.SignedCanonicalBytes()
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(cb)
	return hex.EncodeToString(h[:]), nil
}

// IRI returns the canonical checkpoint:<hash> IRI for this signed
// checkpoint.
func (s Signed) IRI() (string, error) {
	h, err := s.ContentHash()
	if err != nil {
		return "", err
	}
	return "checkpoint:" + h, nil
}

// VerifySignature confirms s.Signature was produced over the envelope's
// canonical bytes by the signer indicated in the signature header.
func (s Signed) VerifySignature(resolver func(fp string) (ed25519.PublicKey, error)) error {
	algo, fp, sigB64, ok := splitSig(s.Signature)
	if !ok {
		return fmt.Errorf("malformed signature %q", s.Signature)
	}
	if algo != "ed25519" {
		return fmt.Errorf("unsupported signature algorithm %q", algo)
	}
	pub, err := resolver(fp)
	if err != nil {
		return fmt.Errorf("resolve %q: %w", fp, err)
	}
	cb, err := s.Checkpoint.CanonicalBytes()
	if err != nil {
		return err
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if !ed25519.Verify(pub, cb, sig) {
		return errors.New("checkpoint signature does not verify")
	}
	return nil
}

func splitSig(s string) (algo, fp, sigB64 string, ok bool) {
	first := -1
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			first = i
			break
		}
	}
	if first < 0 {
		return
	}
	second := -1
	for i := first + 1; i < len(s); i++ {
		if s[i] == ':' {
			second = i
			break
		}
	}
	if second < 0 {
		return
	}
	return s[:first], s[first+1 : second], s[second+1:], true
}
