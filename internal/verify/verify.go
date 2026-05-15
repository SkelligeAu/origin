// Package verify is the determinism oracle: replay the log, rebuild every
// projection, re-evaluate every claim, assert byte-equality at each step.
package verify

// Run is the entry point for the verify subcommand.
func Run(args []string) error {
	return runVerify(args)
}
