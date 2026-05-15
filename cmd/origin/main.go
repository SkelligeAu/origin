// Command origin is the Day-1 prototype CLI for the provenance-backed
// software trust system described in memory/layer-1.md.
//
// One binary. Eight subcommands. No services. Files on disk are canonical.
package main

import (
	"fmt"
	"os"

	"github.com/fitzee/origin/internal/anchor"
	"github.com/fitzee/origin/internal/checkpoint"
	"github.com/fitzee/origin/internal/demo"
	"github.com/fitzee/origin/internal/eval"
	"github.com/fitzee/origin/internal/explain"
	"github.com/fitzee/origin/internal/ingest"
	"github.com/fitzee/origin/internal/peerimport"
	"github.com/fitzee/origin/internal/project"
	"github.com/fitzee/origin/internal/report"
	"github.com/fitzee/origin/internal/verify"
)

const usage = `origin — provenance-backed trust evaluation (Day-1 prototype)

USAGE
  origin <command> [arguments]

COMMANDS
  ingest <github-url>        Fetch raw evidence; emit signed assertions
  project                    Rebuild SQLite projection from assertion log
  eval <subject> --policy <name>
                             Evaluate a policy; write a TrustClaim
  why <claim-id>             Print derivation DAG for a claim
  explain <assertion-id>     Print an assertion + its raw evidence
  verify                     Replay log; assert byte-equality at every step
  report <subject>           Emit a self-contained static HTML report
  export --format=nq         Export assertion log as N-Quads
  import-occurrences <path>  Import a peer's occurrence log (filesystem federation)
        --peer-key <hex|@file> --peer-log-id <log:id> [--register-only]
  demo <github-url|pkg:>     Run full pipeline + bundle into portable tar.gz
        [--output <dir>]
  checkpoint [--output <p>]  Sign current chain head as a checkpoint (raw evidence)
  record-anchor <ckpt-iri> <provider-entry-iri> --evidence <path>
                             Record a transparency-log anchor (observation class)

All canonical state lives under ./data/. No other state exists.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "ingest":
		err = ingest.Run(args)
	case "project":
		err = project.Run(args)
	case "eval":
		err = eval.Run(args)
	case "why":
		err = explain.Why(args)
	case "explain":
		err = explain.Assertion(args)
	case "verify":
		err = verify.Run(args)
	case "report":
		err = report.Run(args)
	case "export":
		err = report.Export(args)
	case "import-occurrences":
		err = peerimport.Run(args)
	case "demo":
		err = demo.Run(args)
	case "checkpoint":
		err = checkpoint.Run(args)
	case "record-anchor":
		err = anchor.Run(args)
	case "-h", "--help", "help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "origin: unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "origin %s: %v\n", cmd, err)
		os.Exit(1)
	}
}
