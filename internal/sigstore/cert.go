package sigstore

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
)

// OIDCSubjectFromDER parses a DER-encoded leaf certificate and returns
// the SAN URI, which for Fulcio-issued certs is the OIDC subject.
func OIDCSubjectFromDER(der []byte) (string, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", fmt.Errorf("parse cert: %w", err)
	}
	subj, _ := extractOIDCFromCert(cert)
	if subj == "" {
		return "", fmt.Errorf("cert has no SAN URI")
	}
	return subj, nil
}

// Fulcio OID extensions used by GitHub Actions OIDC certificates.
// These are documented at https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md
//
// We read the issuer from the v2 extension (1.3.6.1.4.1.57264.1.8). The
// SAN URI is the OIDC subject (the workflow @ ref).
var (
	oidFulcioIssuerV2 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 8}
)

// extractOIDCFromCert pulls the OIDC issuer + subject from a Fulcio-issued
// certificate. Returns (subject, issuer) — both strings, empty when not
// found. Subject is read from the SAN URI; issuer from the Fulcio v2 OID
// extension.
func extractOIDCFromCert(cert *x509.Certificate) (subject, issuer string) {
	for _, u := range cert.URIs {
		if u != nil {
			subject = u.String()
			break
		}
	}
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidFulcioIssuerV2) {
			// The v2 OID payload is a UTF8String wrapped in an ASN.1
			// OCTET STRING. We accept either form gracefully.
			var s string
			if rest, err := asn1.Unmarshal(ext.Value, &s); err == nil && len(rest) == 0 {
				issuer = s
			} else {
				issuer = string(ext.Value)
			}
			break
		}
	}
	return subject, issuer
}
