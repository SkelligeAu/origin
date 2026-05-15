package ingest

import (
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fitzee/origin/internal/assertion"
	"github.com/fitzee/origin/internal/keys"
	"github.com/fitzee/origin/internal/raw"
	"github.com/fitzee/origin/internal/sigstore"
	"github.com/fitzee/origin/internal/vocab"
)

const toolVersion = "origin@0.1.0"

func runIngest(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: origin ingest <github-url|pkg:npm/...>")
	}
	urlStr := args[0]
	directNpm := parseNpmPURL(urlStr)

	dataDir := "data"
	store, err := raw.New(filepath.Join(dataDir, "raw"))
	if err != nil {
		return err
	}
	ring, err := keys.New(filepath.Join(dataDir, "keys"))
	if err != nil {
		return err
	}
	v, err := vocab.LoadLatest("vocab")
	if err != nil {
		return fmt.Errorf("load vocab: %w", err)
	}
	idents, err := assertion.NewIdentityStore(filepath.Join(dataDir, "assertions", "identities"))
	if err != nil {
		return err
	}
	idents.WithVocab(v)

	logID, err := keys.ResolveLogID(dataDir, ring)
	if err != nil {
		return fmt.Errorf("resolve log id: %w", err)
	}
	occs, err := assertion.NewOccurrenceLog(filepath.Join(dataDir, "assertions", "occurrences", "local"), logID)
	if err != nil {
		return err
	}

	priv, fp := ring.Signer()
	attestor := ring.Attestor(toolVersion)
	em := newEmitter(idents, occs, priv, fp, attestor, v)

	if err := writeNormalizerManifest(filepath.Join(dataDir, "normalizers")); err != nil {
		return err
	}

	ctx := context.Background()
	now := func() string { return time.Now().UTC().Format(time.RFC3339) }

	var name, version string
	if directNpm != nil {
		name, version = directNpm.name, directNpm.version
		fmt.Fprintf(os.Stderr, "→ direct coordinate: %s@%s\n", name, version)
	} else {
		owner, repo, err := parseGitHubURL(urlStr)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "→ resolving %s/%s\n", owner, repo)
		if rawURL, body, err := fetchRepoMeta(ctx, owner, repo); err == nil {
			_, _ = store.Put(raw.Metadata{
				Source: "github.api", Endpoint: rawURL,
				RequestParams:  map[string]string{"owner": owner, "repo": repo},
				FetchedAt:      now(),
				Fetcher:        attestor,
				ResponseStatus: 200,
			}, body, priv, fp)
		} else {
			fmt.Fprintf(os.Stderr, "  ! github repo meta: %v\n", err)
		}
		nm, ver, pkgURL, pkgAPI, _, err := resolveNpmCoordinate(ctx, owner, repo)
		if err != nil {
			return fmt.Errorf("resolve npm coordinate: %w", err)
		}
		name, version = nm, ver
		if _, err := store.Put(raw.Metadata{
			Source: "github.api", Endpoint: pkgURL,
			RequestParams:  map[string]string{"owner": owner, "repo": repo, "path": "package.json"},
			FetchedAt:      now(),
			Fetcher:        attestor,
			ResponseStatus: 200,
		}, pkgAPI, priv, fp); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "→ npm coordinate: %s@%s\n", name, version)
	}

	// 3. npm registry: full package document.
	npmURL, npmBody, err := fetchNpmPackage(ctx, name)
	if err != nil {
		return fmt.Errorf("npm registry: %w", err)
	}
	npmEvidence, err := store.Put(raw.Metadata{
		Source: "npm.registry", Endpoint: npmURL,
		RequestParams:  map[string]string{"name": name},
		FetchedAt:      now(),
		Fetcher:        attestor,
		ResponseStatus: 200,
	}, npmBody, priv, fp)
	if err != nil {
		return err
	}
	versionDoc, err := extractNpmVersionDoc(npmBody, version)
	if err != nil {
		return fmt.Errorf("npm extract version: %w", err)
	}
	npmIdents, subjectPURL, err := normalizeNPM(versionDoc, npmEvidence, now())
	if err != nil {
		return fmt.Errorf("normalize npm: %w", err)
	}
	for _, id := range npmIdents {
		if _, _, err := em.emit(id); err != nil {
			return fmt.Errorf("emit npm identity: %w", err)
		}
	}
	fmt.Fprintf(os.Stderr, "→ npm: %d identities for %s\n", len(npmIdents), subjectPURL)

	// 4. OSV vulnerability query.
	osvURL, osvReq, osvBody, err := fetchOSV(ctx, name, version)
	if err != nil {
		return fmt.Errorf("osv: %w", err)
	}
	osvCount := countOSVVulns(osvBody)
	osvEvidence, err := store.Put(raw.Metadata{
		Source: "osv.dev", Endpoint: osvURL,
		RequestParams: map[string]string{
			"name": name, "version": version,
			"request_body_sha256": sha256HexBytes(osvReq),
		},
		FetchedAt:      now(),
		Fetcher:        attestor,
		ResponseStatus: 200,
		ResultCount:    &osvCount,
	}, osvBody, priv, fp)
	if err != nil {
		return err
	}
	osvIdents, _, err := normalizeOSV(osvBody, osvEvidence, now(), subjectPURL)
	if err != nil {
		return err
	}
	for _, id := range osvIdents {
		if _, _, err := em.emit(id); err != nil {
			return fmt.Errorf("emit osv identity: %w", err)
		}
	}
	fmt.Fprintf(os.Stderr, "→ osv: %d vulnerabilities\n", osvCount)

	// 5. Tarball + Rekor + Sigstore attestation verification.
	if tarballURL := extractTarballURL(versionDoc); tarballURL != "" {
		_, tarBytes, _, terr := httpGet(ctx, tarballURL)
		if terr != nil {
			fmt.Fprintf(os.Stderr, "  ! tarball fetch: %v\n", terr)
		} else {
			tarSha := sha256.Sum256(tarBytes)
			tarHash := hex.EncodeToString(tarSha[:])
			tarSha512 := sha512.Sum512(tarBytes)
			tarHash512 := hex.EncodeToString(tarSha512[:])
			if _, err := store.Put(raw.Metadata{
				Source: "npm.tarball", Endpoint: tarballURL,
				FetchedAt: now(), Fetcher: attestor, ResponseStatus: 200,
			}, tarBytes, priv, fp); err != nil {
				return fmt.Errorf("store tarball: %w", err)
			}
			rkURL, rkReq, rkBody, rkCount, rkErr := fetchRekorByHash(ctx, tarHash)
			if rkErr != nil {
				fmt.Fprintf(os.Stderr, "  ! rekor: %v\n", rkErr)
			} else {
				_, _ = store.Put(raw.Metadata{
					Source: "sigstore.rekor", Endpoint: rkURL,
					RequestParams: map[string]string{
						"artifact_sha256":     tarHash,
						"request_body_sha256": sha256HexBytes(rkReq),
					},
					FetchedAt:      now(),
					Fetcher:        attestor,
					ResponseStatus: 200,
					ResultCount:    &rkCount,
				}, rkBody, priv, fp)
				fmt.Fprintf(os.Stderr, "→ rekor: %d log entries for tarball sha256=%s…\n", rkCount, tarHash[:12])
			}

			// 6. Sigstore attestation verification path (invariant 16).
			attURL, attBody, attResp, aerr := fetchNpmAttestations(ctx, name, version)
			if aerr != nil {
				fmt.Fprintf(os.Stderr, "  ! attestations fetch: %v\n", aerr)
			} else if attResp != nil {
				attCount := len(attResp.Attestations)
				_, _ = store.Put(raw.Metadata{
					Source: "npm.attestations", Endpoint: attURL,
					RequestParams:  map[string]string{"name": name, "version": version},
					FetchedAt:      now(),
					Fetcher:        attestor,
					ResponseStatus: 200,
					ResultCount:    &attCount,
				}, attBody, priv, fp)

				if attCount == 0 {
					fmt.Fprintf(os.Stderr, "→ attestations: none published for %s@%s\n", name, version)
				} else {
					prov, perr := findSLSAProvenance(attResp.Attestations)
					if perr != nil {
						fmt.Fprintf(os.Stderr, "→ attestations: %d present, %v\n", attCount, perr)
					} else {
						expectedRepo := extractRepoURL(npmBody)
						if expectedRepo == "" {
							fmt.Fprintf(os.Stderr, "  ! attestation: package has no repository URL; cannot enforce subject coherence — skipping verify\n")
						} else {
							result, verr := sigstore.Verify(prov.Bundle, []sigstore.ArtifactDigest{
								{Algo: "sha512", Hex: tarHash512},
								{Algo: "sha256", Hex: tarHash},
							}, expectedRepo)
							if verr != nil {
								fmt.Fprintf(os.Stderr, "  ! verifier internal error: %v\n", verr)
							} else if !result.Verified {
								if err := emitVerificationFailure(
									store, em, priv, fp, attestor, now(),
									subjectPURL, prov.Bundle,
									attURL, name, version, expectedRepo,
									result,
								); err != nil {
									return fmt.Errorf("emit verification failure: %w", err)
								}
								fmt.Fprintf(os.Stderr, "→ attestation rejected by local verifier (%s): %s\n",
									result.ReasonCode, result.Reason)
							} else {
								identityIRI := sigstoreIdentityIRI(result.OIDCIssuer, result.OIDCSubject)
								// ObservedAt for a verified-form identity is
								// the bundle's Rekor inclusion time, NOT the
								// local clock. This makes the identity ID
								// stable across ingestors who run the same
								// verifier against the same bundle — a Phase-3
								// requirement (layer-3.md §11 criterion #1).
								// Falls back to now() only when the bundle
								// carries no transparency-log timestamp.
								observedAt := extractRekorIntegratedTime(prov.Bundle)
								if observedAt == "" {
									observedAt = now()
								}
								id := assertion.Identity{
									Subject:    subjectPURL,
									Predicate:  "cryptographically_verified_signature_by",
									Object:     assertion.Object{Kind: assertion.ObjectIRI, IRI: identityIRI},
									EvidenceID: storeAttestationEvidence(store, priv, fp, attestor, now(), attURL, name, version, prov.Bundle),
									ObservedAt: observedAt,
									Normalizer: "sigstore-attestation-verifier@v0.1.0",
									Vocab:      VocabVersion,
								}
								if _, _, err := em.emit(id); err != nil {
									return fmt.Errorf("emit verified identity: %w", err)
								}
								fmt.Fprintf(os.Stderr, "✓ cryptographically verified: %s ← %s\n",
									subjectPURL, result.OIDCSubject)
							}
						}
					}
				}
			}
		}
	} else {
		fmt.Fprintf(os.Stderr, "  ! rekor: no dist.tarball in npm record, skipping\n")
	}

	fmt.Fprintf(os.Stderr, "✓ ingest complete; subject = %s\n", subjectPURL)
	return nil
}

func sha256HexBytes(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func countOSVVulns(body []byte) int {
	var doc struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return 0
	}
	return len(doc.Vulns)
}

func extractTarballURL(npmBody []byte) string {
	var doc struct {
		Dist struct {
			Tarball string `json:"tarball"`
		} `json:"dist"`
	}
	if err := json.Unmarshal(npmBody, &doc); err != nil {
		return ""
	}
	return doc.Dist.Tarball
}

// extractRekorIntegratedTime pulls the first tlogEntry's integratedTime
// from a Sigstore bundle (the Rekor log-inclusion time, deterministic
// per bundle) and returns it formatted as RFC 3339 UTC. Returns ""
// when the bundle has no tlog entries or the timestamp is malformed.
func extractRekorIntegratedTime(bundleJSON []byte) string {
	var doc struct {
		VerificationMaterial struct {
			TlogEntries []struct {
				IntegratedTime string `json:"integratedTime"`
			} `json:"tlogEntries"`
		} `json:"verificationMaterial"`
	}
	if err := json.Unmarshal(bundleJSON, &doc); err != nil {
		return ""
	}
	if len(doc.VerificationMaterial.TlogEntries) == 0 {
		return ""
	}
	secsStr := doc.VerificationMaterial.TlogEntries[0].IntegratedTime
	if secsStr == "" {
		return ""
	}
	var secs int64
	for _, c := range secsStr {
		if c < '0' || c > '9' {
			return ""
		}
		secs = secs*10 + int64(c-'0')
	}
	return time.Unix(secs, 0).UTC().Format(time.RFC3339)
}
