# Policy: release_signing@v1
#
# Question this policy answers:
#   "Is there any evidence — reported or verified — that the release has
#    been cryptographically signed, and is there an independent witness?"
#
# Two distinct evidence levels, deliberately separated:
#
#   - registry_reports_signing_key  (OBSERVATION)
#     The ecosystem registry's metadata associates the artifact with a
#     signing key. We did NOT verify the signature against the artifact
#     bytes. Weak evidence: a registry can lie or be compromised.
#
#   - cryptographically_verified_signature_by  (VERIFICATION)
#     A signature on the artifact bytes was fetched and validated by our
#     code against a known public key. Strong evidence.
#     (Day-1 reserved. NOT YET EMITTED. Phase-2 work item.)
#
# The "trusted" verdict requires the VERIFIED form. Day-1 cannot reach
# "trusted" through this policy — that is the correct and honest behaviour.
# A package can at best reach "conditional" today.
#
# Inputs:
#   input.subject                              — package PURL
#   input.registry_reports_signing_key[]       — observed signing key claims
#   input.published_at[]                       — release timestamps (registry)
#   input.published_by[]                       — publisher identity (registry)
#   input.raw_evidence[]                       — every raw fetch we performed
#
# Outputs (closed enum, no numerics):
#   verdict ∈ {trusted, conditional, rejected, insufficient_evidence}
#   qualifiers []string
#   trace[]

package release_signing

import future.keywords.if
import future.keywords.in
import future.keywords.contains

default verdict := "insufficient_evidence"

# Helper: the npm registry reports a signing key for the subject. This is
# an observation; we have NOT verified the signature.
registry_reports_key if {
    some s in input.registry_reports_signing_key
    s.subject == input.subject
    not s.superseded_by
}

# Helper: cryptographic verification has been recorded. Day-1 always false;
# kept here so the policy's verdict ladder is structurally honest.
verified_signature_exists if {
    some v in input.cryptographically_verified_signature_by
    v.subject == input.subject
    not v.superseded_by
}

# Helper: an independent transparency-log witness exists. Day-1 we use
# Rekor presence as a hit; a non-zero result_count means at least one log
# entry references the artifact's digest.
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

# trusted: requires a CRYPTOGRAPHICALLY VERIFIED signature AND an
# independent witness. Day-1 never reaches this branch — verified_signature_
# exists is permanently false until Phase-2 ships verification code.
verdict := "trusted" if {
    verified_signature_exists
    rekor_returned_hits
}

# conditional: registry claims a signing key AND Rekor returned at least
# one hit, but we did not verify the signature ourselves. Strongest
# verdict reachable Day-1.
verdict := "conditional" if {
    registry_reports_key
    rekor_returned_hits
}

# conditional (downgraded): registry reports a key but Rekor returned no
# entries. We have a one-sided registry claim and the independent witness
# we consulted did not corroborate it.
verdict := "conditional" if {
    registry_reports_key
    rekor_was_queried
    not rekor_returned_hits
}

# insufficient_evidence: no signing-key claim from any source. NOT
# rejected — absence of evidence is not evidence of compromise.
verdict := "insufficient_evidence" if {
    not registry_reports_key
    not verified_signature_exists
}

# Qualifiers explicitly name the evidence level so downstream consumers
# cannot mistake reported claims for verified ones.
qualifiers contains "registry_reports_signing_key" if registry_reports_key
qualifiers contains "no_cryptographic_verification_performed" if {
    registry_reports_key
    not verified_signature_exists
}
qualifiers contains "cryptographically_verified_signature_present" if verified_signature_exists
qualifiers contains "rekor_transparency_log_hit" if rekor_returned_hits
qualifiers contains "rekor_returned_no_entries" if {
    rekor_was_queried
    not rekor_returned_hits
}
qualifiers contains "no_signing_key_reported" if not registry_reports_key
qualifiers contains "npm_registry_consulted" if npm_was_queried

trace contains "registry_reports_key"        if registry_reports_key
trace contains "verified_signature_exists"   if verified_signature_exists
trace contains "rekor_was_queried"           if rekor_was_queried
trace contains "rekor_returned_hits"         if rekor_returned_hits
trace contains "npm_was_queried"             if npm_was_queried
