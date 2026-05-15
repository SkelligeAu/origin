// Package assertion implements the canonical fact (Identity) and the
// local ingestion event (Occurrence) used by origin.
//
// Phase 3 split: AssertionIdentity is the content-addressable fact;
// AssertionOccurrence is the local record of who recorded it, when, in
// which chain. Two ingestors observing the same source bytes through the
// same normalizer produce the same Identity bytes; their Occurrences
// differ by attestor, log_id, and chain position.
//
// See memory/layer-3.md for the structural rationale and
// memory/epistemic-model.v1.md §6.3 for the model.
//
// This file contains the shared Object type (the discriminated union for
// the object position of an assertion quad) and the signature helper.
// Identity lives in identity.go; Occurrence lives in occurrence.go.
package assertion

import (
	"errors"
	"fmt"
)

// ObjectKind distinguishes the three legal object shapes.
type ObjectKind string

const (
	ObjectIRI     ObjectKind = "iri"
	ObjectLiteral ObjectKind = "literal"
	ObjectRef     ObjectKind = "ref" // identity-id or claim-id reference
)

// Object is the object position of an assertion quad. Exactly one of the
// three forms is populated, signalled by Kind.
type Object struct {
	Kind     ObjectKind `json:"kind"`
	IRI      string     `json:"iri,omitempty"`
	Literal  string     `json:"literal,omitempty"`
	Datatype string     `json:"datatype,omitempty"`
	Ref      string     `json:"ref,omitempty"`
}

// Validate the object's discriminated-union invariant.
func (o Object) Validate() error {
	switch o.Kind {
	case ObjectIRI:
		if o.IRI == "" {
			return errors.New("iri object has empty iri")
		}
		if o.Literal != "" || o.Datatype != "" || o.Ref != "" {
			return errors.New("iri object has stray fields")
		}
	case ObjectLiteral:
		if o.Literal == "" {
			return errors.New("literal object has empty literal")
		}
		if o.Datatype == "" {
			return errors.New("literal object has empty datatype")
		}
		if o.IRI != "" || o.Ref != "" {
			return errors.New("literal object has stray fields")
		}
	case ObjectRef:
		if o.Ref == "" {
			return errors.New("ref object has empty ref")
		}
		if o.IRI != "" || o.Literal != "" || o.Datatype != "" {
			return errors.New("ref object has stray fields")
		}
	default:
		return fmt.Errorf("unknown object kind %q", o.Kind)
	}
	return nil
}

// splitSig parses a signature header of form "algo:fp:b64sig".
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
