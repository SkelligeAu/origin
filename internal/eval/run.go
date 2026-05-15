package eval

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	_ "modernc.org/sqlite"

	"github.com/SkelligeAu/origin/internal/keys"
	"github.com/open-policy-agent/opa/rego"
)

const evaluatorVersion = "origin@0.1.0/evaluator"

func runEval(args []string) error {
	if len(args) < 3 || args[1] != "--policy" {
		return errors.New("usage: origin eval <subject> --policy <name>")
	}
	subject := args[0]
	policyName := args[2]
	dataDir := "data"

	claim, err := Evaluate(subject, policyName, dataDir)
	if err != nil {
		return err
	}

	// Sign + persist. Signing is a side-effect of writing; verify
	// re-derives without signing.
	ring, err := keys.New(filepath.Join(dataDir, "keys"))
	if err != nil {
		return err
	}
	priv, fp := ring.Signer()
	cb, err := canonicalClaimBytes(claim)
	if err != nil {
		return err
	}
	sig, err := ed25519SignClaim(priv, fp, cb)
	if err != nil {
		return err
	}
	claim.Signature = sig

	claimsDir := filepath.Join(dataDir, "claims")
	if err := os.MkdirAll(claimsDir, 0755); err != nil {
		return err
	}
	out, err := json.MarshalIndent(claim, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(claimsDir, claim.ID+".json")
	if err := os.WriteFile(path, out, 0644); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "✓ %s/%s → %s\n", claim.PolicyID, claim.PolicyVersion, claim.Verdict)
	for _, q := range claim.Qualifiers {
		fmt.Fprintf(os.Stderr, "  · %s\n", q)
	}
	fmt.Fprintf(os.Stderr, "claim: %s\n", path)
	return nil
}

// Evaluate is the pure evaluation pipeline — exported so verify can
// re-derive claims without writing them. The returned TrustClaim has its
// ID computed from canonical bytes (EvaluatedAt excluded from canonical)
// but no Signature; the caller signs before persisting if it wishes.
//
// Day-1 risk #7 closure: re-running Evaluate against an unchanged
// projection + unchanged policy yields a byte-identical claim ID.
func Evaluate(subject, policySpec, dataDir string) (*TrustClaim, error) {
	manifest, err := LoadPolicy(policySpec)
	if err != nil {
		return nil, err
	}

	db, err := sql.Open("sqlite", filepath.Join(dataDir, "projections", "index.sqlite"))
	if err != nil {
		return nil, err
	}
	defer db.Close()

	manifestPath := filepath.Join(dataDir, "projections", "MANIFEST.json")
	pmHashBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, fmt.Errorf("read projection manifest: %w", err)
	}
	pmHash := sha256.Sum256(pmHashBytes)
	pmHashHex := hex.EncodeToString(pmHash[:])
	// Read identities_hash from the projection manifest. This is the
	// fact-side hash that participates in claim identity. Falls back to
	// empty (claim becomes ingestor-specific) only when MANIFEST.json
	// predates Phase 3.
	var manifestDoc map[string]any
	if err := json.Unmarshal(pmHashBytes, &manifestDoc); err != nil {
		return nil, fmt.Errorf("parse projection manifest: %w", err)
	}
	identitiesHash, _ := manifestDoc["identities_hash"].(string)

	snap, err := buildSnapshot(db, subject, manifest)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	results, err := evaluatePolicy(ctx, manifest, snap.asOPAInput())
	if err != nil {
		return nil, err
	}
	verdict, _ := results["verdict"].(string)
	if !allowedVerdicts[verdict] {
		return nil, fmt.Errorf("policy emitted disallowed verdict %q", verdict)
	}
	qualifiers := asStringSlice(results["qualifiers"])
	trace := asStringSlice(results["trace"])
	sort.Strings(qualifiers)
	sort.Strings(trace)

	var missing []string
	for _, p := range manifest.RequiredPredicates {
		hasRow := false
		for _, r := range snap.ByPred[p] {
			if r["subject"] == subject && r["superseded_by"] == nil {
				hasRow = true
				break
			}
		}
		if !hasRow {
			missing = append(missing, p)
		}
	}
	sort.Strings(missing)

	claim := &TrustClaim{
		Subject:                subject,
		PolicyID:               manifest.ID,
		PolicyVersion:          manifest.Version,
		PolicyHash:             manifest.PolicyHash,
		Query:                  manifest.Queries["verdict"],
		Verdict:                verdict,
		Qualifiers:             qualifiers,
		EvaluatedAt:            time.Now().UTC().Format(time.RFC3339),
		EvaluatorVersion:       evaluatorVersion,
		IdentitiesHash:         identitiesHash,
		ProjectionManifestHash: pmHashHex,
		VocabVersion:           manifest.VocabRequired,
		NormalizerVersions:     snap.Consumed.NormalizerVers,
		IdentityIDsConsumed:    snap.Consumed.IdentityIDs,
		RawEvidenceIDsConsumed: snap.Consumed.RawEvidenceIDs,
		Derivation: Derivation{
			RulesFired:        trace,
			MissingPredicates: missing,
			InputCounts:       snap.inputCounts(),
			OccurrencesCited:  snap.Consumed.OccurrencesByID,
		},
	}
	cb, err := canonicalClaimBytes(claim)
	if err != nil {
		return nil, err
	}
	idH := sha256.Sum256(cb)
	claim.ID = hex.EncodeToString(idH[:])
	return claim, nil
}

func evaluatePolicy(ctx context.Context, m *PolicyManifest, input map[string]any) (map[string]any, error) {
	out := map[string]any{}
	for name, query := range m.Queries {
		r := rego.New(
			rego.Query(query),
			rego.Module(filepath.Join(m.Path, "policy.rego"), m.PolicyRego),
			rego.Input(input),
		)
		rs, err := r.Eval(ctx)
		if err != nil {
			return nil, fmt.Errorf("eval %s: %w", query, err)
		}
		if len(rs) == 0 {
			out[name] = nil
			continue
		}
		// Single-expression query: result is rs[0].Expressions[0].Value.
		if len(rs[0].Expressions) == 0 {
			out[name] = nil
			continue
		}
		out[name] = rs[0].Expressions[0].Value
	}
	return out, nil
}

func asStringSlice(v any) []string {
	if v == nil {
		return nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
