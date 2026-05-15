// Package ingest implements `origin ingest <github-url>`.
package ingest

import "errors"

// Run is the entry point for the ingest subcommand.
// Implementation lives across multiple files in this package (sources/*.go,
// normalize.go, run.go).
func Run(args []string) error {
	return runIngest(args)
}

// ErrUnsupportedHost is returned when the URL is not a recognized host.
var ErrUnsupportedHost = errors.New("unsupported source host (Day-1 supports github.com only)")
