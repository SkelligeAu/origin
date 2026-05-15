// Package explain implements `origin why` and `origin explain`.
package explain

// Why pretty-prints the derivation DAG for a TrustClaim.
func Why(args []string) error {
	return runWhy(args)
}

// Assertion pretty-prints an assertion plus its raw evidence record.
func Assertion(args []string) error {
	return runExplain(args)
}
