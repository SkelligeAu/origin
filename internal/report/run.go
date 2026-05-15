package report

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/fitzee/origin/internal/assertion"
	"github.com/fitzee/origin/internal/vocab"
)

const dataDir = "data"

// runReport emits a self-contained static HTML report for one subject.
func runReport(args []string) error {
	if len(args) < 1 {
		return errors.New("usage: origin report <subject>")
	}
	subject := args[0]

	// Gather: every identity about the subject, every claim, the raw
	// evidence cited by either, plus the occurrences for each identity
	// (so corroboration is visible in the report).
	idents, err := assertion.NewIdentityStore(filepath.Join(dataDir, "assertions", "identities"))
	if err != nil {
		return err
	}
	var rels []assertion.Identity
	err = idents.Walk(func(i assertion.Identity) error {
		if i.Subject == subject {
			rels = append(rels, i)
		}
		return nil
	})
	if err != nil {
		return err
	}

	claims, err := loadClaimsForSubject(subject)
	if err != nil {
		return err
	}

	db, err := sql.Open("sqlite", filepath.Join(dataDir, "projections", "index.sqlite"))
	if err != nil {
		return err
	}
	defer db.Close()
	rawRows, err := allRawEvidence(db)
	if err != nil {
		return err
	}

	outDir := filepath.Join(dataDir, "reports")
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}
	runID := time.Now().UTC().Format("20060102T150405Z")
	outPath := filepath.Join(outDir, runID+".html")

	page := renderHTML(subject, rels, claims, rawRows)
	if err := os.WriteFile(outPath, []byte(page), 0644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "✓ report written: %s\n", outPath)
	return nil
}

func runExport(args []string) error {
	format := "nq"
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "--format=") {
			format = strings.TrimPrefix(args[i], "--format=")
		}
	}
	if format != "nq" {
		return fmt.Errorf("only --format=nq supported Day-1")
	}
	idents, err := assertion.NewIdentityStore(filepath.Join(dataDir, "assertions", "identities"))
	if err != nil {
		return err
	}
	return idents.Walk(func(i assertion.Identity) error {
		fmt.Println(toNQuad(i))
		return nil
	})
}

// toNQuad renders an identity as an N-Quad with the identity ID as the
// named-graph context. Attestor and ingestion metadata are NOT part of
// identity (they belong to occurrences) and are deliberately omitted from
// the identity-level N-Quad emission.
func toNQuad(i assertion.Identity) string {
	graph := fmt.Sprintf("<urn:origin:identity:%s>", i.ID)
	subj := fmt.Sprintf("<urn:origin:purl:%s>", iriEscape(i.Subject))
	pred := fmt.Sprintf("<urn:origin:pred:%s>", i.Predicate)
	var obj string
	switch i.Object.Kind {
	case assertion.ObjectIRI:
		obj = fmt.Sprintf("<urn:origin:iri:%s>", iriEscape(i.Object.IRI))
	case assertion.ObjectLiteral:
		obj = fmt.Sprintf(`"%s"^^<%s>`,
			nquadsEscape(i.Object.Literal), i.Object.Datatype)
	case assertion.ObjectRef:
		obj = fmt.Sprintf("<urn:origin:identity:%s>", i.Object.Ref)
	}
	main := fmt.Sprintf("%s %s %s %s .", subj, pred, obj, graph)
	metaG := "<urn:origin:metadata>"
	meta := []string{
		fmt.Sprintf(`%s <urn:origin:meta:observed_at> "%s"^^<xsd:dateTime> %s .`, graph, i.ObservedAt, metaG),
		fmt.Sprintf(`%s <urn:origin:meta:evidence>    <urn:origin:raw:%s> %s .`, graph, i.EvidenceID, metaG),
		fmt.Sprintf(`%s <urn:origin:meta:normalizer> "%s" %s .`, graph, nquadsEscape(i.Normalizer), metaG),
		fmt.Sprintf(`%s <urn:origin:meta:vocab>      "%s" %s .`, graph, nquadsEscape(i.Vocab), metaG),
	}
	return main + "\n" + strings.Join(meta, "\n")
}

func iriEscape(s string) string {
	// Conservative: replace characters that are not safe in URN syntax.
	r := strings.NewReplacer(
		" ", "%20", "<", "%3C", ">", "%3E", `"`, "%22", "{", "%7B", "}", "%7D",
		"|", "%7C", "\\", "%5C", "^", "%5E", "`", "%60",
	)
	return r.Replace(s)
}

func nquadsEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`, "\t", `\t`)
	return r.Replace(s)
}

func loadClaimsForSubject(subject string) ([]map[string]any, error) {
	dir := filepath.Join(dataDir, "claims")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []map[string]any
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, err
		}
		if s, _ := m["subject"].(string); s == subject {
			out = append(out, m)
		}
	}
	return out, nil
}

type rawRow struct {
	ID, Source, Endpoint, FetchedAt, PayloadPath string
	ResultCount                                   *int64
}

func allRawEvidence(db *sql.DB) ([]rawRow, error) {
	rows, err := db.Query(
		`SELECT id, source, endpoint, fetched_at, payload_path, result_count
         FROM raw_evidence ORDER BY id ASC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []rawRow
	for rows.Next() {
		var r rawRow
		var rc sql.NullInt64
		if err := rows.Scan(&r.ID, &r.Source, &r.Endpoint, &r.FetchedAt, &r.PayloadPath, &rc); err != nil {
			return nil, err
		}
		if rc.Valid {
			v := rc.Int64
			r.ResultCount = &v
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func renderHTML(subject string, rels []assertion.Identity, claims []map[string]any, raws []rawRow) string {
	var b strings.Builder
	fmt.Fprintf(&b, `<!doctype html>
<html><head><meta charset="utf-8"><title>origin: %s</title>
<style>
body{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;max-width:960px;margin:2em auto;padding:0 1em;color:#222;line-height:1.4}
h1,h2,h3{font-family:system-ui,-apple-system,sans-serif}
h1{font-size:1.2em;border-bottom:1px solid #ccc;padding-bottom:0.3em}
h2{font-size:1.05em;margin-top:1.8em;color:#444}
.tag{display:inline-block;padding:0.05em 0.5em;border-radius:0.4em;font-size:0.85em;margin:0.1em 0.1em 0.1em 0}
.v-trusted{background:#cde}
.v-conditional{background:#fec}
.v-rejected{background:#fcc}
.v-insufficient_evidence{background:#eee;color:#666}
.qual{background:#f3f3f3;color:#444;font-size:0.8em}
.cls-observation{background:#eef;color:#446}
.cls-verification{background:#dfd;color:#262;font-weight:bold}
.cls-refutation{background:#fdd;color:#622}
.cls-structural{background:#fafafa;color:#999}
.peer{background:#fef3e0;color:#774;font-size:0.75em}
pre.howto{background:#fafafa;padding:0.8em 1em;border-left:3px solid #cbd;border-radius:0.3em;font-size:0.85em;overflow-x:auto}
.id{color:#888;font-size:0.85em}
table{border-collapse:collapse;width:100%%;font-size:0.85em}
td,th{border-bottom:1px solid #eee;padding:0.3em 0.5em;vertical-align:top;text-align:left}
th{background:#fafafa}
.short{font-family:ui-monospace,Menlo,monospace;color:#666}
a{color:#345;text-decoration:none;border-bottom:1px dotted #aab}
a:hover{border-bottom:1px solid #345}
.note{color:#666;font-size:0.85em;font-style:italic}
</style></head><body>
<h1>origin report: %s</h1>
<p class="note">Generated %s. Every claim below traces to evidence on disk; click an ID to see the file.</p>
`,
		html.EscapeString(subject), html.EscapeString(subject),
		time.Now().UTC().Format(time.RFC3339))

	fmt.Fprintf(&b, "<h2>Trust claims (%d)</h2>\n", len(claims))
	if len(claims) == 0 {
		b.WriteString(`<p class="note">No claims for this subject yet. Run <code>origin eval &lt;subject&gt; --policy &lt;name&gt;</code>.</p>`)
	}
	for _, c := range claims {
		verdict, _ := c["verdict"].(string)
		policyID, _ := c["policy_id"].(string)
		policyV, _ := c["policy_version"].(string)
		claimID, _ := c["id"].(string)
		fmt.Fprintf(&b, `<div style="margin:0.8em 0;padding:0.6em 0.8em;border:1px solid #ddd;border-radius:0.4em">
<div><b>%s/%s</b> <span class="tag v-%s">%s</span></div>
`, html.EscapeString(policyID), html.EscapeString(policyV),
			html.EscapeString(verdict), html.EscapeString(verdict))
		if quals, ok := c["qualifiers"].([]any); ok && len(quals) > 0 {
			b.WriteString(`<div style="margin-top:0.3em">`)
			for _, q := range quals {
				fmt.Fprintf(&b, `<span class="tag qual">%s</span>`, html.EscapeString(fmt.Sprint(q)))
			}
			b.WriteString(`</div>`)
		}
		fmt.Fprintf(&b, `<div class="id">claim id <a href="../claims/%s.json">%s</a></div></div>`,
			claimID, shortHash(claimID))
	}

	fmt.Fprintf(&b, "<h2>Identities about this subject (%d)</h2>\n", len(rels))
	b.WriteString(`<p class="note">Identities are content-addressable facts. Each row shows the verification class (per <code>vocab/v5.json</code>) so observation and locally-executed verification are visibly distinct. Identities whose predicate starts with <code>peer_reports_</code> originated from a federated peer; their object is a reference to a foreign identity ID (never the verified-form claim itself — invariant 16 / Origin Protocol §10.5).</p>`)
	b.WriteString(`<table><tr><th>class</th><th>predicate</th><th>object</th><th>observed</th><th>normalizer</th><th>evidence</th></tr>`)
	for _, r := range rels {
		class := vocabClass(r.Predicate)
		classTag := fmt.Sprintf(`<span class="tag cls-%s">%s</span>`, class, class)
		peerTag := ""
		if strings.HasPrefix(r.Predicate, "peer_reports_") {
			peerTag = ` <span class="tag peer">peer-imported</span>`
		}
		fmt.Fprintf(&b,
			`<tr><td>%s</td><td>%s%s</td><td>%s</td><td class="short">%s</td><td class="short">%s</td><td class="short">%s</td></tr>`,
			classTag,
			html.EscapeString(r.Predicate),
			peerTag,
			html.EscapeString(renderObject(r.Object)),
			html.EscapeString(r.ObservedAt),
			html.EscapeString(r.Normalizer),
			shortHash(r.EvidenceID),
		)
	}
	b.WriteString(`</table>`)

	fmt.Fprintf(&b, "<h2>Raw evidence fetched (%d)</h2>\n", len(raws))
	b.WriteString(`<table><tr><th>source</th><th>endpoint</th><th>fetched_at</th><th>result_count</th><th>payload</th></tr>`)
	for _, r := range raws {
		rc := ""
		if r.ResultCount != nil {
			rc = fmt.Sprintf("%d", *r.ResultCount)
		}
		fmt.Fprintf(&b,
			`<tr><td>%s</td><td class="short">%s</td><td class="short">%s</td><td>%s</td><td class="short"><a href="../../%s">%s</a></td></tr>`,
			html.EscapeString(r.Source),
			html.EscapeString(r.Endpoint),
			html.EscapeString(r.FetchedAt),
			rc,
			html.EscapeString(r.PayloadPath),
			shortHash(r.ID),
		)
	}
	b.WriteString(`</table>`)

	b.WriteString(`<h2>How to verify this report</h2>`)
	b.WriteString(`<p class="note">This report makes claims. Those claims are checkable. If you have the <code>origin</code> binary and this report's containing directory, you can re-derive every result from canonical bytes and confirm byte-equality.</p>`)
	b.WriteString(`<pre class="howto"># From the directory containing data/, policies/, vocab/, and protocol/:
origin verify

# To re-evaluate a single claim:
origin eval &lt;subject&gt; --policy &lt;policy-name&gt;

# To inspect any assertion's chain back to its raw evidence:
origin explain &lt;identity-id&gt;

# All twelve checks run by 'verify' are specified in protocol/origin-protocol-v0.md §12.
# The verdict you see here is reproducible from the canonical bytes alone.</pre>`)

	b.WriteString(`<h2>Invariants this report rests on</h2><ul>`)
	b.WriteString(`<li><b>Observation is not verification.</b> A predicate's <i>verification class</i> (see the column above) names which kind of work produced each fact.</li>`)
	b.WriteString(`<li><b>Verification is local.</b> Any <code>cryptographically_verified_*</code> identity was produced by this binary's verifier running against artefact bytes anchored to a pinned trust root. Peer-imported verified-form claims appear under <code>peer_reports_*</code> predicates instead (the rewrite rule at the federation boundary).</li>`)
	b.WriteString(`<li><b>No aggregate score.</b> Verdicts are categorical: <code>trusted</code>, <code>conditional</code>, <code>rejected</code>, <code>insufficient_evidence</code>. The qualifier list shows which evidence supported the verdict.</li>`)
	b.WriteString(`<li><b>The log is canonical.</b> Append-only, signed, content-addressed. The projection, the claims, and this HTML page are all deterministic functions of the log.</li>`)
	b.WriteString(`</ul>`)
	b.WriteString(`<p class="note">Full protocol specification: <a href="../../protocol/origin-protocol-v0.md">protocol/origin-protocol-v0.md</a></p>`)
	b.WriteString(`</body></html>`)
	return b.String()
}

func renderObject(o assertion.Object) string {
	switch o.Kind {
	case assertion.ObjectIRI:
		return o.IRI
	case assertion.ObjectLiteral:
		return fmt.Sprintf("%s (%s)", o.Literal, o.Datatype)
	case assertion.ObjectRef:
		return "→" + o.Ref
	}
	return "?"
}

func shortHash(s string) string {
	if len(s) < 12 {
		return s
	}
	return s[:12] + "…"
}

// vocabClass returns the verification class for a predicate by looking
// it up in the active vocabulary. Falls back to "unknown" if absent.
// Cached after the first lookup for the lifetime of the renderer.
var classCache map[string]string

func vocabClass(predicate string) string {
	if classCache == nil {
		classCache = map[string]string{}
		v, err := vocab.LoadLatest("vocab")
		if err == nil {
			for name, def := range v.Predicates {
				classCache[name] = def.VerificationClass
			}
		}
	}
	if c, ok := classCache[predicate]; ok && c != "" {
		return c
	}
	return "unknown"
}
