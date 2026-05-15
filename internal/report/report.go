// Package report emits a self-contained static HTML report and the N-Quads
// export view.
package report

// Run renders the HTML report for a subject.
func Run(args []string) error {
	return runReport(args)
}

// Export emits the assertion log in N-Quads form.
func Export(args []string) error {
	return runExport(args)
}
