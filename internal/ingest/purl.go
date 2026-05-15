package ingest

import "strings"

// npmCoord is the minimal coordinate the ingest pipeline needs: the
// registry-side name (e.g. "@sindresorhus/is") and the exact version
// string ("8.1.0").
type npmCoord struct {
	name    string
	version string
}

// parseNpmPURL recognises "pkg:npm/<name>@<version>". Returns nil if the
// input is not an npm PURL.
//
// Examples:
//   pkg:npm/example@1.2.3
//   pkg:npm/@scope/example@1.2.3
//
// We accept the scoped form with the leading "@" intact because every
// real-world npm consumer expects to see scoped names that way; the PURL
// spec technically requires percent-encoding the "@" but the npm
// registry's own API accepts both, and our use of PURL is internal.
func parseNpmPURL(s string) *npmCoord {
	const prefix = "pkg:npm/"
	if !strings.HasPrefix(s, prefix) {
		return nil
	}
	rest := s[len(prefix):]
	// Find the LAST "@" — the one separating name from version. (Scoped
	// names start with "@" so a naive first-index split is wrong.)
	at := strings.LastIndex(rest, "@")
	if at <= 0 || at == len(rest)-1 {
		return nil
	}
	name := rest[:at]
	version := rest[at+1:]
	if name == "" || version == "" {
		return nil
	}
	return &npmCoord{name: name, version: version}
}
