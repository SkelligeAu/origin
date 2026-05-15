package ingest

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/SkelligeAu/origin/internal/assertion"
)

// Normalizer versions are constants in code. They are also written into
// data/normalizers/manifest.json so the projection can record which
// version produced each identity.
const (
	NormalizerNPM   = "npm-registry-record@v0.1.0"
	NormalizerOSV   = "osv-vuln-query@v0.1.0"
	NormalizerRekor = "rekor-search@v0.1.0"
	NormalizerGH    = "github-repo-meta@v0.1.0"
	VocabVersion    = "v6"
)

// idBase is a small constructor for an Identity envelope with the
// per-fetch fields filled in.
type idBase struct {
	EvidenceID string
	ObservedAt string
	Normalizer string
}

func (b idBase) new(subj, pred string, obj assertion.Object) assertion.Identity {
	return assertion.Identity{
		Subject:    subj,
		Predicate:  pred,
		Object:     obj,
		EvidenceID: b.EvidenceID,
		ObservedAt: b.ObservedAt,
		Normalizer: b.Normalizer,
		Vocab:      VocabVersion,
	}
}

// normalizeNPM converts an npm registry per-version document into a list
// of identity envelopes. The PURL form is "pkg:npm/<name>@<version>".
func normalizeNPM(raw []byte, evidenceID string, fetchedAt string) ([]assertion.Identity, string, error) {
	var doc struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Time    string `json:"time,omitempty"`
		NpmUser *struct {
			Name string `json:"name"`
		} `json:"_npmUser"`
		Dist struct {
			Signatures []struct {
				Keyid string `json:"keyid"`
				Sig   string `json:"sig"`
			} `json:"signatures"`
			Integrity string `json:"integrity,omitempty"`
			Shasum    string `json:"shasum,omitempty"`
			Tarball   string `json:"tarball,omitempty"`
		} `json:"dist"`
		Dependencies map[string]string `json:"dependencies"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, "", fmt.Errorf("npm decode: %w", err)
	}
	if doc.Name == "" || doc.Version == "" {
		return nil, "", fmt.Errorf("npm record missing name/version")
	}
	subj := fmt.Sprintf("pkg:npm/%s@%s", doc.Name, doc.Version)

	// observed_at: prefer the per-version time entry; fall back to fetch time.
	observed := fetchedAt
	if doc.Time != "" {
		if _, err := time.Parse(time.RFC3339, doc.Time); err == nil {
			observed = doc.Time
		}
	}

	base := idBase{
		EvidenceID: evidenceID,
		ObservedAt: observed,
		Normalizer: NormalizerNPM,
	}

	var out []assertion.Identity

	if observed != "" {
		out = append(out, base.new(subj, "published_at", assertion.Object{
			Kind:     assertion.ObjectLiteral,
			Literal:  observed,
			Datatype: "xsd:dateTime",
		}))
	}

	if doc.NpmUser != nil && doc.NpmUser.Name != "" {
		out = append(out, base.new(subj, "published_by", assertion.Object{
			Kind: assertion.ObjectIRI,
			IRI:  fmt.Sprintf("npm:user:%s", doc.NpmUser.Name),
		}))
	}

	// registry_reports_signing_key — observation class. The registry
	// claims a signing key; we have NOT verified the signature against
	// artifact bytes. Verified form is emitted by the verifier path.
	for _, s := range doc.Dist.Signatures {
		if s.Keyid == "" {
			continue
		}
		out = append(out, base.new(subj, "registry_reports_signing_key", assertion.Object{
			Kind: assertion.ObjectIRI,
			IRI:  fmt.Sprintf("npm:key:%s", s.Keyid),
		}))
	}

	for name, constraint := range doc.Dependencies {
		obj := fmt.Sprintf("pkg:npm/%s@%s", name, constraint)
		out = append(out, base.new(subj, "depends_on", assertion.Object{
			Kind: assertion.ObjectIRI,
			IRI:  obj,
		}))
	}

	return out, subj, nil
}

// normalizeOSV converts an OSV query response into affected_by identities.
func normalizeOSV(raw []byte, evidenceID string, fetchedAt string, subject string) ([]assertion.Identity, int, error) {
	var doc struct {
		Vulns []struct {
			ID       string `json:"id"`
			Modified string `json:"modified,omitempty"`
		} `json:"vulns"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, 0, fmt.Errorf("osv decode: %w", err)
	}
	base := idBase{
		EvidenceID: evidenceID,
		ObservedAt: fetchedAt,
		Normalizer: NormalizerOSV,
	}
	var out []assertion.Identity
	for _, v := range doc.Vulns {
		if v.ID == "" {
			continue
		}
		out = append(out, base.new(subject, "affected_by", assertion.Object{
			Kind: assertion.ObjectIRI,
			IRI:  "osv:" + v.ID,
		}))
	}
	return out, len(doc.Vulns), nil
}
