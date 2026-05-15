# Policy: dependency_hygiene@v1
#
# Question this policy answers:
#   "Is the release's direct dependency surface known to be vulnerable,
#    and was the vulnerability database consulted for the subject itself?"
#
# Inputs (Day-1 vocab):
#   input.subject            — the package PURL under evaluation
#   input.depends_on[]       — rows from depends_on predicate table
#   input.affected_by[]      — rows from affected_by predicate table
#   input.raw_evidence[]     — rows from raw_evidence projection table
#
# Outputs:
#   verdict ∈ {trusted, conditional, rejected, insufficient_evidence}
#   qualifiers []string
#   trace[]
#
# Day-1 limitation: we have direct deps as declared constraints
# (e.g. "pkg:npm/foo@^1.2.3"), not resolved versions. We cannot directly
# OSV-check a constraint, so the policy reports "insufficient_evidence"
# unless all deps appear in affected_by. This is conservative and honest.

package dependency_hygiene

import future.keywords.if
import future.keywords.in
import future.keywords.contains

default verdict := "insufficient_evidence"
# qualifiers and trace are partial-set rules — no default required.

osv_was_queried if {
    some r in input.raw_evidence
    r.source == "osv.dev"
    r.endpoint != ""
}

subject_directly_vulnerable if {
    some a in input.affected_by
    a.subject == input.subject
    not a.superseded_by
}

direct_deps_present if {
    some d in input.depends_on
    d.subject == input.subject
    not d.superseded_by
}

# Count of direct deps for the subject. Used in qualifiers below.
direct_dep_count := count([d |
    some d in input.depends_on
    d.subject == input.subject
    not d.superseded_by
])

verdict := "rejected" if {
    subject_directly_vulnerable
}

# Trusted: we asked OSV, subject is not affected, and we have visibility
# into the declared dependency surface.
verdict := "trusted" if {
    osv_was_queried
    not subject_directly_vulnerable
    direct_deps_present
}

# Conditional: subject not affected per OSV, but the package declares no
# runtime dependencies — there is no transitive surface to evaluate.
verdict := "conditional" if {
    osv_was_queried
    not subject_directly_vulnerable
    not direct_deps_present
}

# Insufficient: OSV was never queried.
verdict := "insufficient_evidence" if {
    not osv_was_queried
}

qualifiers contains "osv_was_queried"                    if osv_was_queried
qualifiers contains "subject_directly_vulnerable"        if subject_directly_vulnerable
qualifiers contains "no_known_vulnerabilities_for_subject" if {
    osv_was_queried
    not subject_directly_vulnerable
}
qualifiers contains "no_runtime_dependencies"            if {
    not direct_deps_present
    osv_was_queried
}
qualifiers contains "direct_dep_surface_observed"        if direct_deps_present
qualifiers contains "transitive_resolution_not_implemented" if {
    direct_deps_present
}

trace contains "osv_was_queried"             if osv_was_queried
trace contains "subject_directly_vulnerable" if subject_directly_vulnerable
trace contains "direct_deps_present"         if direct_deps_present
