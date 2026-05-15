// Package demo implements `origin demo <github-url|pkg:npm/...>`.
//
// The demo command runs the full pipeline (ingest → project → eval ×
// release_signing & dependency_hygiene → verify → report) in a fresh
// temporary working directory, then bundles the resulting data/ tree
// plus the HTML report plus the protocol spec into a single portable
// tar.gz archive.
//
// The recipient of the tarball can `tar -xzf` it and run `origin verify`
// against the unpacked directory to reproduce every claim end-to-end —
// the protocol made visible.
package demo

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fitzee/origin/internal/eval"
	"github.com/fitzee/origin/internal/ingest"
	"github.com/fitzee/origin/internal/project"
	"github.com/fitzee/origin/internal/report"
	"github.com/fitzee/origin/internal/verify"
)

// Run is the CLI entry point.
func Run(args []string) error {
	var input, outputDir string
	i := 0
	for i < len(args) {
		a := args[i]
		switch {
		case a == "--output":
			if i+1 >= len(args) {
				return errors.New("--output requires a value")
			}
			outputDir = args[i+1]
			i += 2
		case strings.HasPrefix(a, "--"):
			return fmt.Errorf("unknown flag %q", a)
		default:
			if input != "" {
				return fmt.Errorf("unexpected positional %q", a)
			}
			input = a
			i++
		}
	}
	if input == "" {
		return errors.New("usage: origin demo <github-url|pkg:npm/...> [--output <dir>]")
	}
	if outputDir == "" {
		outputDir = "."
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}

	origCwd, err := os.Getwd()
	if err != nil {
		return err
	}
	// Resolve outputDir to absolute BEFORE chdir.
	absOutput, err := filepath.Abs(outputDir)
	if err != nil {
		return err
	}

	tmpDir, err := os.MkdirTemp("", "origin-demo-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	// Stage vocab/ and policies/ into the temp dir so the pipeline can
	// run there in isolation from the user's primary working directory.
	if err := copyTree(filepath.Join(origCwd, "vocab"), filepath.Join(tmpDir, "vocab")); err != nil {
		return fmt.Errorf("stage vocab: %w", err)
	}
	if err := copyTree(filepath.Join(origCwd, "policies"), filepath.Join(tmpDir, "policies")); err != nil {
		return fmt.Errorf("stage policies: %w", err)
	}
	// Stage the protocol spec into the temp dir so the tarball is
	// self-describing.
	if err := copyFile(
		filepath.Join(origCwd, "protocol", "origin-protocol-v0.md"),
		filepath.Join(tmpDir, "protocol", "origin-protocol-v0.md"),
	); err != nil {
		fmt.Fprintf(os.Stderr, "  ! could not stage protocol spec: %v\n", err)
	}

	if err := os.Chdir(tmpDir); err != nil {
		return err
	}
	defer os.Chdir(origCwd)

	fmt.Fprintf(os.Stderr, "── demo: ingest ──\n")
	if err := ingest.Run([]string{input}); err != nil {
		return fmt.Errorf("ingest: %w", err)
	}

	fmt.Fprintf(os.Stderr, "── demo: project ──\n")
	if err := project.Run(nil); err != nil {
		return fmt.Errorf("project: %w", err)
	}

	// Determine the subject from the freshly-ingested log so we know
	// what to eval/report against.
	subject, err := lastIngestedSubject(tmpDir)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "── demo: eval release_signing ──\n")
	if err := eval.Run([]string{subject, "--policy", "release_signing"}); err != nil {
		return fmt.Errorf("eval release_signing: %w", err)
	}
	fmt.Fprintf(os.Stderr, "── demo: eval dependency_hygiene ──\n")
	if err := eval.Run([]string{subject, "--policy", "dependency_hygiene"}); err != nil {
		return fmt.Errorf("eval dependency_hygiene: %w", err)
	}

	fmt.Fprintf(os.Stderr, "── demo: verify ──\n")
	if err := verify.Run(nil); err != nil {
		return fmt.Errorf("verify: %w", err)
	}

	fmt.Fprintf(os.Stderr, "── demo: report ──\n")
	if err := report.Run([]string{subject}); err != nil {
		return fmt.Errorf("report: %w", err)
	}

	// Bundle.
	shortSubject := shortenSubject(subject)
	stamp := time.Now().UTC().Format("20060102T150405Z")
	tarName := fmt.Sprintf("origin-demo-%s-%s.tar.gz", shortSubject, stamp)
	tarPath := filepath.Join(absOutput, tarName)
	if err := makeTarball(tmpDir, tarPath); err != nil {
		return fmt.Errorf("tarball: %w", err)
	}

	fmt.Fprintf(os.Stderr, "\n✓ demo bundle: %s\n", tarPath)
	fmt.Fprintf(os.Stderr, "\nTo verify the bundle:\n")
	fmt.Fprintf(os.Stderr, "    mkdir -p /tmp/origin-demo-check && tar -xzf %s -C /tmp/origin-demo-check\n", tarPath)
	fmt.Fprintf(os.Stderr, "    cd /tmp/origin-demo-check && origin verify\n\n")
	fmt.Fprintf(os.Stderr, "Open the report:\n")
	fmt.Fprintf(os.Stderr, "    open /tmp/origin-demo-check/data/reports/*.html\n")
	return nil
}

// lastIngestedSubject returns the subject of the most recent identity
// in the temp data dir. (Ingest currently produces 1 subject; we read
// it back from the on-disk log.)
func lastIngestedSubject(tmpDir string) (string, error) {
	identsDir := filepath.Join(tmpDir, "data", "assertions", "identities")
	entries, err := os.ReadDir(identsDir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		f, err := os.Open(filepath.Join(identsDir, e.Name()))
		if err != nil {
			return "", err
		}
		defer f.Close()
		// Read first line; identities for one ingest share subject.
		var line []byte
		buf := make([]byte, 4096)
		for {
			n, err := f.Read(buf)
			if n > 0 {
				for _, b := range buf[:n] {
					if b == '\n' {
						goto done
					}
					line = append(line, b)
				}
			}
			if err != nil {
				break
			}
		}
	done:
		// Crude JSON field extraction to avoid pulling assertion package.
		s := string(line)
		key := `"subject":"`
		i := strings.Index(s, key)
		if i < 0 {
			return "", errors.New("no subject field in first identity record")
		}
		rest := s[i+len(key):]
		j := strings.Index(rest, `"`)
		if j < 0 {
			return "", errors.New("malformed subject field")
		}
		return rest[:j], nil
	}
	return "", errors.New("no identities found; ingest produced no facts")
}

func shortenSubject(s string) string {
	r := strings.NewReplacer("/", "_", "@", "_at_", ":", "_", " ", "_")
	out := r.Replace(s)
	if len(out) > 40 {
		out = out[:40]
	}
	return out
}

// makeTarball gzip-tars the contents of srcDir into dstPath.
func makeTarball(srcDir, dstPath string) error {
	f, err := os.Create(dstPath)
	if err != nil {
		return err
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	srcDir = filepath.Clean(srcDir)
	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		// NOTE: the private signing key (data/keys/ingestor.ed25519) is
		// INCLUDED in the tarball. Phase 4 trades the small risk of "the
		// recipient could sign new assertions with this key" against the
		// clean property "recipient runs `origin verify` and reproduces
		// every check end-to-end." A future read-only Ring mode (Phase
		// 5 candidate) would let us exclude the private key while still
		// supporting verify.
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = rel
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		ff, err := os.Open(path)
		if err != nil {
			return err
		}
		defer ff.Close()
		_, err = io.Copy(tw, ff)
		return err
	})
}

func copyTree(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		return copyFile(path, target)
	})
}

func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}
