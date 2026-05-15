// Package project rebuilds the SQLite projection from the assertion log.
package project

import "errors"

// Run is the entry point for the project subcommand.
func Run(args []string) error {
	return runProject(args)
}

// ErrSchemaDrift is returned when the projection's schema_hash in the
// manifest differs from the current code.
var ErrSchemaDrift = errors.New("projection schema drift")
