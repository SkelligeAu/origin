// Package eval runs a policy against the projection and writes a TrustClaim.
package eval

// Run is the entry point for the eval subcommand.
func Run(args []string) error {
	return runEval(args)
}
