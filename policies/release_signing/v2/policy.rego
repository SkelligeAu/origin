# Policy: release_signing@v2
#
# Phase-2 evolution of v1: same shape, but `trusted` is now reachable when
# this binary has cryptographically verified the artifact's signature
# itself (invariant 16). v1 remains in place at policies/release_signing/v1/
# for replaying historical claims.
#
# Two distinct evidence levels, deliberately separated:
#
#   - registry_reports_signing_key  (OBSERVATION)
#     A registry's metadata associates the artifact with a signing key.
#     Weak evidence: a registry can lie or be compromised.
#
#   - cryptographically_verified_signature_by  (LOCAL VERIFICATION)
#     This binary, in some prior run, executed Sigstore/Fulcio
#     verification end-to-end against the artifact bytes and the
#     procedure succeeded. Strong evidence.
#
# `trusted` requires the VERIFICATION form. `conditional` is reached when
# we have only the OBSERVATION form, regardless of Rekor.
#
# Inputs:
#   input.subject                                     — package PURL
#   input.registry_reports_signing_key[]              — observed claims
#   input.cryptographically_verified_signature_by[]   — verified facts
#   input.published_at[], input.published_by[]        — supporting context
#   input.raw_evidence[]                              — every fetch made

package release_signing

import future.keywords.if
import future.keywords.in
import future.keywords.contains

default verdict := "insufficient_evidence"

registry_reports_key if {
    some s in input.registry_reports_signing_key
    s.subject == input.subject
    not s.superseded_by
}

verified_signature_exists if {
    some v in input.cryptographically_verified_signature_by
    v.subject == input.subject
    not v.superseded_by
}

rekor_was_queried if {
    some r in input.raw_evidence
    r.source == "sigstore.rekor"
}

rekor_returned_hits if {
    some r in input.raw_evidence
    r.source == "sigstore.rekor"
    r.result_count > 0
}

npm_was_queried if {
    some r in input.raw_evidence
    r.source == "npm.registry"
}

attestations_were_fetched if {
    some r in input.raw_evidence
    r.source == "npm.attestations"
}

# trusted: this binary verified the signature itself. Independent witness
# (Rekor hit) is a bonus but not required — local verification IS the
# witness, anchored to a pinned trust root.
verdict := "trusted" if {
    verified_signature_exists
}

# conditional: registry attests a signing key but we did NOT verify it
# ourselves. This is the strongest verdict reachable for packages that
# don't publish Sigstore provenance.
verdict := "conditional" if {
    registry_reports_key
    not verified_signature_exists
}

# insufficient_evidence: nothing at all. Not rejected — absence ≠ harm.
verdict := "insufficient_evidence" if {
    not registry_reports_key
    not verified_signature_exists
}

qualifiers contains "cryptographically_verified_signature_present" if verified_signature_exists
qualifiers contains "registry_reports_signing_key" if registry_reports_key
qualifiers contains "no_cryptographic_verification_performed" if {
    registry_reports_key
    not verified_signature_exists
}
qualifiers contains "no_signing_key_observed_anywhere" if {
    not registry_reports_key
    not verified_signature_exists
}
qualifiers contains "rekor_transparency_log_hit" if rekor_returned_hits
qualifiers contains "rekor_returned_no_entries" if {
    rekor_was_queried
    not rekor_returned_hits
}
qualifiers contains "npm_registry_consulted" if npm_was_queried
qualifiers contains "npm_attestations_consulted" if attestations_were_fetched

trace contains "registry_reports_key"      if registry_reports_key
trace contains "verified_signature_exists" if verified_signature_exists
trace contains "rekor_was_queried"         if rekor_was_queried
trace contains "rekor_returned_hits"       if rekor_returned_hits
trace contains "npm_was_queried"           if npm_was_queried
trace contains "attestations_were_fetched" if attestations_were_fetched
