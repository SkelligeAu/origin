// Package sigstore wraps github.com/sigstore/sigstore-go for the verifier.
//
// Root-of-trust policy:
//   Origin pins the Sigstore public-good trusted root in source at
//   trusted_root_public_good.json and embeds it via go:embed. The trusted
//   root file was copied from sigstore-go v1.1.4's example assets, which
//   matches the public-good Fulcio CAs, Rekor tlog, and CT logs operated
//   by the Sigstore community. We never fetch a trust root at runtime.
//
// Why this matters (invariant 16):
//   A verified-form assertion (cryptographically_verified_signature_by)
//   may only be emitted from locally executed verification. Local
//   verification requires a root of trust that was chosen by us, not
//   delivered to us at runtime. If a future operator wants to use a
//   different Sigstore instance (a private rekor + fulcio deployment,
//   say), they must edit this file in source. That edit is a visible,
//   attributable act recorded by git history.
//
// Rotation:
//   Public-good roots evolve. When Sigstore rotates, we update this file
//   intentionally in a versioned release and document the change. We do
//   NOT add live TUF fetching — that would let upstream silently change
//   our root of trust without our consent, which collapses the chain
//   that invariant 16 protects.
package sigstore

import (
	_ "embed"

	"github.com/sigstore/sigstore-go/pkg/root"
)

//go:embed trusted_root_public_good.json
var trustedRootPublicGoodJSON []byte

// TrustedRoot returns the parsed, pinned Sigstore public-good trusted
// root. Subsequent calls share the same parsed object.
func TrustedRoot() (*root.TrustedRoot, error) {
	return root.NewTrustedRootFromJSON(trustedRootPublicGoodJSON)
}
