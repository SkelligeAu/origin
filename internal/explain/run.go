package explain

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"

	"github.com/SkelligeAu/origin/internal/assertion"
	"github.com/SkelligeAu/origin/internal/keys"
	"github.com/SkelligeAu/origin/internal/raw"
)

const dataDir = "data"

// runWhy prints a derivation DAG for a TrustClaim.
func runWhy(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: origin why <claim-id>")
	}
	id := args[0]
	path := filepath.Join(dataDir, "claims", id+".json")
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("claim not found: %w", err)
	}
	var c map[string]any
	if err := json.Unmarshal(b, &c); err != nil {
		return err
	}

	idents, err := assertion.NewIdentityStore(filepath.Join(dataDir, "assertions", "identities"))
	if err != nil {
		return err
	}
	rawStore, err := raw.New(filepath.Join(dataDir, "raw"))
	if err != nil {
		return err
	}
	db, err := sql.Open("sqlite", filepath.Join(dataDir, "projections", "index.sqlite"))
	if err != nil {
		return err
	}
	defer db.Close()

	fmt.Printf("Subject:     %s\n", str(c["subject"]))
	fmt.Printf("Policy:      %s/%s  (hash %s)\n",
		str(c["policy_id"]), str(c["policy_version"]),
		shortHash(str(c["policy_hash"])))
	fmt.Printf("Verdict:     %s\n", str(c["verdict"]))
	fmt.Printf("Evaluated:   %s\n", str(c["evaluated_at"]))

	if quals, ok := c["qualifiers"].([]any); ok && len(quals) > 0 {
		fmt.Println("\nQualifiers:")
		for _, q := range quals {
			fmt.Printf("  · %s\n", q)
		}
	}

	if d, ok := c["derivation"].(map[string]any); ok {
		if rules, ok := d["rules_fired"].([]any); ok && len(rules) > 0 {
			fmt.Println("\nRules fired:")
			for _, r := range rules {
				fmt.Printf("  · %s\n", r)
			}
		}
		if mp, ok := d["missing_predicates"].([]any); ok && len(mp) > 0 {
			fmt.Println("\nMissing predicates:")
			for _, p := range mp {
				fmt.Printf("  · %s\n", p)
			}
		}
		if counts, ok := d["input_counts"].(map[string]any); ok {
			fmt.Println("\nInput row counts:")
			for k, v := range counts {
				fmt.Printf("  %-40s %v\n", k, v)
			}
		}
	}

	if iids, ok := c["identity_ids_consumed"].([]any); ok && len(iids) > 0 {
		fmt.Printf("\nIdentities consumed (%d):\n", len(iids))
		for _, a := range iids {
			iid := str(a)
			rec, ok, _ := idents.Find(iid)
			if !ok {
				fmt.Printf("  · %s  [MISSING from identity store]\n", iid)
				continue
			}
			obj := renderObject(rec.Object)
			fmt.Printf("  · %s\n", shortHash(iid))
			fmt.Printf("      %s %s %s\n", rec.Subject, rec.Predicate, obj)
			fmt.Printf("      observed=%s\n", rec.ObservedAt)
			fmt.Printf("      evidence=%s  normalizer=%s\n", shortHash(rec.EvidenceID), rec.Normalizer)
			// Show occurrences corroborating this identity.
			if d, ok := c["derivation"].(map[string]any); ok {
				if oc, ok := d["occurrences_cited"].(map[string]any); ok {
					if list, ok := oc[iid].([]any); ok && len(list) > 0 {
						fmt.Printf("      occurrences (%d):\n", len(list))
						for _, oid := range list {
							meta := lookupOccurrence(db, str(oid))
							fmt.Printf("        - %s  attestor=%s  role=%s  log=%s  at=%s\n",
								shortHash(str(oid)),
								meta.attestor, meta.role, meta.logID, meta.ingestedAt)
						}
					}
				}
			}
		}
	}

	if rids, ok := c["raw_evidence_ids_consumed"].([]any); ok && len(rids) > 0 {
		fmt.Printf("\nRaw evidence consumed (%d):\n", len(rids))
		for _, r := range rids {
			rid := str(r)
			meta, _, _, err := rawStore.Get(rid)
			if err != nil {
				fmt.Printf("  · %s  [MISSING]\n", rid)
				continue
			}
			rc := ""
			if meta.ResultCount != nil {
				rc = fmt.Sprintf("  result_count=%d", *meta.ResultCount)
			}
			fmt.Printf("  · %s  source=%s%s\n", shortHash(rid), meta.Source, rc)
			fmt.Printf("      %s\n", meta.Endpoint)
		}
	}

	fmt.Printf("\nProjection manifest: %s\n", shortHash(str(c["projection_manifest_hash"])))
	fmt.Printf("Evaluator:           %s\n", str(c["evaluator_version"]))
	fmt.Printf("Vocab:               %s\n", str(c["vocab_version"]))
	fmt.Printf("Claim signature:     %s\n", shortHash(str(c["signature"])))
	return nil
}

type occMeta struct {
	attestor, role, logID, ingestedAt string
}

func lookupOccurrence(db *sql.DB, id string) occMeta {
	var m occMeta
	_ = db.QueryRow(
		`SELECT attestor, attestor_role, log_id, ingested_at FROM occurrences WHERE id = ?`,
		id,
	).Scan(&m.attestor, &m.role, &m.logID, &m.ingestedAt)
	return m
}

// runExplain prints an identity plus its raw evidence and occurrence(s).
func runExplain(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: origin explain <identity-id|occurrence-id>")
	}
	id := args[0]
	idents, err := assertion.NewIdentityStore(filepath.Join(dataDir, "assertions", "identities"))
	if err != nil {
		return err
	}
	rawStore, err := raw.New(filepath.Join(dataDir, "raw"))
	if err != nil {
		return err
	}
	ring, err := keys.New(filepath.Join(dataDir, "keys"))
	if err != nil {
		return err
	}
	logID, err := keys.ResolveLogID(dataDir, ring)
	if err != nil {
		return err
	}
	occs, err := assertion.NewOccurrenceLog(filepath.Join(dataDir, "assertions", "occurrences", "local"), logID)
	if err != nil {
		return err
	}

	// Try identity first.
	if i, ok, err := idents.Find(id); err == nil && ok {
		printIdentity(i, occs, rawStore)
		return nil
	}
	// Else try occurrence.
	if o, ok, err := occs.Find(id); err == nil && ok {
		printOccurrence(o, idents, rawStore)
		return nil
	}
	return fmt.Errorf("id %s not found as either identity or occurrence", id)
}

func printIdentity(i assertion.Identity, occs *assertion.OccurrenceLog, rawStore *raw.Store) {
	fmt.Printf("Identity:     %s\n", i.ID)
	fmt.Printf("Subject:      %s\n", i.Subject)
	fmt.Printf("Predicate:    %s\n", i.Predicate)
	fmt.Printf("Object:       %s\n", renderObject(i.Object))
	fmt.Printf("Observed at:  %s\n", i.ObservedAt)
	fmt.Printf("Normalizer:   %s\n", i.Normalizer)
	fmt.Printf("Vocab:        %s\n", i.Vocab)
	if i.Revises != nil {
		fmt.Printf("Revises:      %s\n", *i.Revises)
	}
	fmt.Printf("\nOccurrences:\n")
	count := 0
	_ = occs.Walk(func(o assertion.Occurrence) error {
		if o.IdentityID != i.ID {
			return nil
		}
		count++
		fmt.Printf("  · %s  attestor=%s  role=%s\n", shortHash(o.ID), o.Attestor, o.AttestorRole)
		fmt.Printf("    log=%s  at=%s\n", o.LogID, o.IngestedAt)
		fmt.Printf("    chain: prev=%s  this=%s\n", shortHash(o.PrevChainHash), shortHash(o.ChainHash))
		fmt.Printf("    sig:   %s\n", shortHash(o.Signature))
		return nil
	})
	if count == 0 {
		fmt.Println("  (none — orphan identity)")
	}

	fmt.Printf("\nEvidence:     %s\n", i.EvidenceID)
	meta, _, metaPath, err := rawStore.Get(i.EvidenceID)
	if err != nil {
		fmt.Printf("  ! evidence not resolvable: %v\n", err)
		return
	}
	fmt.Printf("  source:     %s\n", meta.Source)
	fmt.Printf("  endpoint:   %s\n", meta.Endpoint)
	fmt.Printf("  fetched_at: %s\n", meta.FetchedAt)
	fmt.Printf("  fetcher:    %s\n", meta.Fetcher)
	fmt.Printf("  payload:    %s\n", meta.PayloadPath)
	fmt.Printf("  metadata:   %s\n", metaPath)
}

func printOccurrence(o assertion.Occurrence, idents *assertion.IdentityStore, rawStore *raw.Store) {
	fmt.Printf("Occurrence:   %s\n", o.ID)
	fmt.Printf("Identity:     %s\n", o.IdentityID)
	fmt.Printf("Attestor:     %s\n", o.Attestor)
	fmt.Printf("Role:         %s\n", o.AttestorRole)
	fmt.Printf("Log:          %s\n", o.LogID)
	fmt.Printf("Ingested at:  %s\n", o.IngestedAt)
	fmt.Printf("Chain prev:   %s\n", o.PrevChainHash)
	fmt.Printf("Chain this:   %s\n", o.ChainHash)
	fmt.Printf("Signature:    %s\n", o.Signature)

	if i, ok, err := idents.Find(o.IdentityID); err == nil && ok {
		fmt.Printf("\nNames identity:\n")
		fmt.Printf("  %s %s %s\n", i.Subject, i.Predicate, renderObject(i.Object))
		fmt.Printf("  observed=%s  normalizer=%s\n", i.ObservedAt, i.Normalizer)
		fmt.Printf("  evidence=%s\n", shortHash(i.EvidenceID))
	}
}

func str(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

func shortHash(s string) string {
	if len(s) < 16 {
		return s
	}
	if strings.HasPrefix(s, "ed25519:") {
		parts := strings.SplitN(s, ":", 3)
		if len(parts) == 3 {
			tail := parts[2]
			if len(tail) > 12 {
				tail = tail[:12] + "…"
			}
			return parts[0] + ":" + parts[1] + ":" + tail
		}
	}
	return s[:12] + "…"
}

func renderObject(o assertion.Object) string {
	switch o.Kind {
	case assertion.ObjectIRI:
		return o.IRI
	case assertion.ObjectLiteral:
		return fmt.Sprintf("%q^^%s", o.Literal, o.Datatype)
	case assertion.ObjectRef:
		return "→" + o.Ref
	default:
		return "?"
	}
}
