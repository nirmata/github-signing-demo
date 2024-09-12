package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/in-toto/in-toto-golang/in_toto"
	"github.com/pkg/errors"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

type VerificationOptions struct {
	PredicateType *string
	Limit         *int    // hardcoded for fetching artifact
	OIDCIssuer    *string // hardcoded
	Subject       *string
}

type VerificationResult struct {
	Bundle *Bundle
	Result *verify.VerificationResult
	Desc   *v1.Descriptor
}

type Bundle struct {
	ProtoBundle   *bundle.ProtobufBundle
	DSSE_Envelope *in_toto.Statement
}

func main() {
	opts := VerificationOptions{}
	image := flag.String("image", "", "image used for verification")
	opts.PredicateType = flag.String("predicate-type", "", "filter bundles based on the predicate type")
	opts.Limit = flag.Int("limit", 100, "max number of attestations to fetch")
	opts.OIDCIssuer = flag.String("issuer", "https://token.actions.githubusercontent.com", "custom oidc issuer")
	opts.Subject = flag.String("subject", "", "identity of the issuer")

	flag.Parse()
	if len(os.Args) == 1 {
		fmt.Println("Usage: pass image with appropriate flags to verify images using github artifact attestations")
		flag.PrintDefaults()
	}

	verifysigstore(image, opts)
}

func verifysigstore(image *string, opts VerificationOptions) {

	ref, err := name.ParseReference(*image)
	if err != nil {
		panic(errors.Wrapf(err, "failed to parse image reference: %v", image))
	}

	bundles, desc, err := fetchBundles(ref, *opts.Limit, *opts.PredicateType)
	if err != nil {
		panic(err)
	}

	policy, err := buildPolicy(desc, opts)
	if err != nil {
		panic(err)
	}

	verifyOpts := buildVerifyOptions(opts)
	trustedMaterial, err := getTrustedRoot(context.TODO())
	if err != nil {
		panic(err)
	}

	results, err := verifyBundles(bundles, desc, trustedMaterial, policy, verifyOpts)
	if err != nil {
		panic(err)
	}

	val, err := json.MarshalIndent(results[0].Bundle.DSSE_Envelope, "", " ")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(val))
}

func fetchBundles(ref name.Reference, limit int, predicateType string) ([]*Bundle, *v1.Descriptor, error) {
	bundles := make([]*Bundle, 0)

	remoteOpts := []remote.Option{
		remote.WithAuthFromKeychain(authn.DefaultKeychain),
	}

	desc, err := remote.Head(ref, remoteOpts...)
	if err != nil {
		return nil, nil, err
	}

	referrers, err := remote.Referrers(ref.Context().Digest(desc.Digest.String()), remoteOpts...)
	if err != nil {
		return nil, nil, err
	}

	referrersDescs, err := referrers.IndexManifest()
	if err != nil {
		return nil, nil, err
	}

	if len(referrersDescs.Manifests) > limit {
		return nil, nil, fmt.Errorf("failed to fetch referrers: to many referrers found, max limit is %d", limit)
	}

	for _, manifestDesc := range referrersDescs.Manifests {
		if !strings.HasPrefix(manifestDesc.ArtifactType, "application/vnd.dev.sigstore.bundle") {
			continue
		}

		refImg, err := remote.Image(ref.Context().Digest(manifestDesc.Digest.String()), remoteOpts...)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to fetch referrer image: %w", err)
		}
		layers, err := refImg.Layers()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to fetch referrer layer: %w", err)
		}
		layerBytes, err := layers[0].Uncompressed()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to fetch referrer layer: %w", err)
		}
		bundleBytes, err := io.ReadAll(layerBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to fetch referrer layer: %w", err)
		}
		b := &bundle.ProtobufBundle{}
		err = b.UnmarshalJSON(bundleBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal bundle: %w", err)
		}
		bundles = append(bundles, &Bundle{ProtoBundle: b})
	}

	if predicateType != "" {
		filteredBundles := make([]*Bundle, 0)
		for _, b := range bundles {
			dsseEnvelope := b.ProtoBundle.Bundle.GetDsseEnvelope()
			if dsseEnvelope != nil {
				if dsseEnvelope.PayloadType != "application/vnd.in-toto+json" {
					continue
				}
				var intotoStatement in_toto.Statement
				if err := json.Unmarshal([]byte(dsseEnvelope.Payload), &intotoStatement); err != nil {
					continue
				}

				if intotoStatement.PredicateType == predicateType {
					filteredBundles = append(filteredBundles, &Bundle{
						ProtoBundle:   b.ProtoBundle,
						DSSE_Envelope: &intotoStatement,
					})
				}
			}
		}
		return filteredBundles, desc, nil
	}

	return bundles, desc, nil
}

func buildPolicy(desc *v1.Descriptor, opts VerificationOptions) (verify.PolicyBuilder, error) {
	digest, err := hex.DecodeString(desc.Digest.Hex)
	if err != nil {
		return verify.PolicyBuilder{}, err
	}
	artifactDigestVerificationOption := verify.WithArtifactDigest(desc.Digest.Algorithm, digest)

	// TODO: Add full regexp support to sigstore and cosign
	// Verify images only has subject field, and no subject regexp, subject cannot be passed to subject regexp
	// because then string containing the subjects will also work. We should just add an issuer regexp
	// Solve this in a seperate PR,
	// See: https://github.com/sigstore/cosign/blob/7c20052077a81d667526af879ec40168899dde1f/pkg/cosign/verify.go#L339-L356
	subjectRegexp := ""
	if strings.Contains(*opts.Subject, "*") {
		subjectRegexp = *opts.Subject
		*opts.Subject = ""
	}
	id, err := verify.NewShortCertificateIdentity(*opts.OIDCIssuer, "", *opts.Subject, subjectRegexp)
	if err != nil {
		return verify.PolicyBuilder{}, err
	}
	return verify.NewPolicy(artifactDigestVerificationOption, verify.WithCertificateIdentity(id)), nil
}

func buildVerifyOptions(opts VerificationOptions) []verify.VerifierOption {
	var verifierOptions []verify.VerifierOption
	// if authority.RFC3161Timestamp != nil {
	// verifierOptions = append(verifierOptions, verify.WithSignedTimestamps(1))
	// } else {
	// verifierOptions = append(verifierOptions, verify.WithTransparencyLog(1))
	// }
	verifierOptions = append(verifierOptions, verify.WithSignedTimestamps(1), verify.WithObserverTimestamps(0))
	return verifierOptions
}

func getTrustedRoot(ctx context.Context) (*root.TrustedRoot, error) {
	out, err := base64.StdEncoding.DecodeString("ewogInNpZ25hdHVyZXMiOiBbCiAgewogICAia2V5aWQiOiAiNGY0ZDFkZDc1ZjJkN2YzODYwZTNhMDY4ZDdiZWQ5MGRlYzVmMGZhYWZjYmUxYWNlN2ZiN2Q5NWQyOWUwNzIyOCIsCiAgICJzaWciOiAiIgogIH0sCiAgewogICAia2V5aWQiOiAiNWUwMWM5YTBiMjY0MWE4OTY1YTRhNzRlN2RmMGJjN2IyZDgyNzhhMmMzY2EwY2Y3YTNmMmY3ODNkM2M2OTgwMCIsCiAgICJzaWciOiAiIgogIH0sCiAgewogICAia2V5aWQiOiAiZWI4ZWZmMzdmOTNhZjJmYWFiYTUxOWYzNDFkZWNlYzNjZWNkM2VlYWZjYWNlMzI5NjZkYjk3MjM4NDJjOGE2MiIsCiAgICJzaWciOiAiIgogIH0sCiAgewogICAia2V5aWQiOiAiYTEwNTEzYTVhYjYxYWNkMGM2YjZmYmUwNTA0ODU2ZWFkMThmM2IxN2M0ZmFiYmUzZmE4NDhjNzlhNWExODdjZiIsCiAgICJzaWciOiAiMzA0NTAyMjEwMDg0YzlmMjk2ZWI1YjY3MmU0NDIxMzA5NjY1M2RkN2ZlZGNkMjQ3Nzg1MDQ0ZGVjNjQ4ZjBmM2JlN2IwY2Q1MTAwMjIwNzg2NzgyMmI2ZDFhODU5NjlhNTY5N2U3NzQyNTczMTllM2Q4NzIzZmE2ZDQwM2FlMDcyOTgwYjcyYWNmYTUwZCIKICB9LAogIHsKICAgImtleWlkIjogImQ2YTg5ZTIzZmIyMjgwMWEwZDExODZiZjFiZGQwMDdlMjI4ZjY1YThhYTk5NjRkMjRkMDZjYjVmYmIwY2U5MWMiLAogICAic2lnIjogIjMwNDUwMjIwMGYwZmI0YThiMTEzOWVjOWY4ZDMzNjc2OGZmMWI4M2Y5NWMzOGE4NjEzZmNjZjg4YTE5ZjZlZDNjYTAyMTE5YjAyMjEwMDgyMzU1MTdjMWRkMjdjZmM4NGYzODY3Y2JiYjgyMThmZmFkZGM1ZDczZmNmNjQ5NzEzNTE4YmZhMWE5M2E0YWEiCiAgfSwKICB7CiAgICJrZXlpZCI6ICI4YjQ5OGE4MGExYjdhZjE4OGMxMGM5YWJkZjZhYWRlODFkMTRmYWFmZmNkZTJhYmNkNjA2M2JhYTY3M2ViZDEyIiwKICAgInNpZyI6ICIzMDQ0MDIyMDY4ZTU5Y2JkMGUyNTk4NDVkYThhM2Y1YzBmMDJkODk1YTBiZDBmOGQwMTBjYjk0YTE0YWUzZDRjZTBmNDM2YmYwMjIwMGVjODFkODNmMzkyNGIyNjQ0NTkxZDQ1MmVjNTM5Yjk3MTNkNzA3ZTcxODc4YTllY2ExYWI1NDUyMjY3NjVlNyIKICB9LAogIHsKICAgImtleWlkIjogIjg4NzM3Y2NkYWM3YjQ5Y2MyMzdlOWFhZWFkODFiZTJhNDAyNzhiODg2YTY5M2Q4MTQ5YTE5Y2Y1NDNmMDkzZDMiLAogICAic2lnIjogIjMwNDYwMjIxMDBlMDlmYTZjZWRhYzc0ZDJmY2UwMzg4YzQ2MTZhOTM4ZGQ4MTgyOTZlNWNiMmUxZmJiYmVhMWQxOGE2NjMwOGU5MDIyMTAwYmZlZjMwNmVmNTg5YjZjN2VkNjMzODdmOGMzMzg4NWMwMzc2OTYzNDQ3ODRmZWVhMjJlNGQ2ZjU1ZTg3NmEzZiIKICB9LAogIHsKICAgImtleWlkIjogIjUzOWRkZTQ0MDE0Yzg1MGZlNmVlYjhiMjk5ZWI3ZGFlMmUxZjRiZjgzNDU0Yjk0OWU5OGFhNzM1NDJjZGM2NWEiLAogICAic2lnIjogIjMwNDYwMjIxMDBlZDNjNTk5NzM4OGM5YTA5MjY0ZTdiZWNiNzQ0ODFlOTU2N2FhNTQ2MWVjNjZmM2Q3MzExZTQ2MWFjNjcyNTUxMDIyMTAwYzQ3ODllNDFjNjE4MTA3MTkzZjA0NTdkYzYzYjAwMzczZGEzYmVmMTcxZDY5ZWRhMDcyMzZiNDIyNTQ3MDlmMCIKICB9CiBdLAogInNpZ25lZCI6IHsKICAiX3R5cGUiOiAicm9vdCIsCiAgImNvbnNpc3RlbnRfc25hcHNob3QiOiB0cnVlLAogICJleHBpcmVzIjogIjIwMjQtMTItMjBUMTM6MjU6MTVaIiwKICAia2V5cyI6IHsKICAgIjRmNGQxZGQ3NWYyZDdmMzg2MGUzYTA2OGQ3YmVkOTBkZWM1ZjBmYWFmY2JlMWFjZTdmYjdkOTVkMjllMDcyMjgiOiB7CiAgICAia2V5dHlwZSI6ICJlY2RzYSIsCiAgICAia2V5dmFsIjogewogICAgICJwdWJsaWMiOiAiLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS1cbk1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRU5raTdhWlZpcHM1U2dSekNkL09tMENHelFLWS9cbm52ODRnaXFWRG1kd2IyeXM4Mlo2c29GTGFzdllZRUVRY3dxYUMxNzBuOWdyOTN3SFVnUGM3OTZ1SkE9PVxuLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tXG4iCiAgICB9LAogICAgInNjaGVtZSI6ICJlY2RzYS1zaGEyLW5pc3RwMjU2IiwKICAgICJ4LXR1Zi1vbi1jaS1rZXlvd25lciI6ICJAYXNodG9tIgogICB9LAogICAiNTM5ZGRlNDQwMTRjODUwZmU2ZWViOGIyOTllYjdkYWUyZTFmNGJmODM0NTRiOTQ5ZTk4YWE3MzU0MmNkYzY1YSI6IHsKICAgICJrZXl0eXBlIjogImVjZHNhIiwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICItLS0tLUJFR0lOIFBVQkxJQyBLRVktLS0tLVxuTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFbEQwbzJzT1pOOW4zUktRN1B0TUxBb1hqKzJBaVxubjRQS1QvcGZuekRsTkxyRDNWVFF3Q2M0c1I0dCtPTHU0S1ErcWsra1hrUjlZdUJzdTNiZEpaMU9Xdz09XG4tLS0tLUVORCBQVUJMSUMgS0VZLS0tLS1cbiIKICAgIH0sCiAgICAic2NoZW1lIjogImVjZHNhLXNoYTItbmlzdHAyNTYiLAogICAgIngtdHVmLW9uLWNpLWtleW93bmVyIjogIkBuZXJkbmVoYSIKICAgfSwKICAgIjVlMDFjOWEwYjI2NDFhODk2NWE0YTc0ZTdkZjBiYzdiMmQ4Mjc4YTJjM2NhMGNmN2EzZjJmNzgzZDNjNjk4MDAiOiB7CiAgICAia2V5dHlwZSI6ICJlY2RzYSIsCiAgICAia2V5dmFsIjogewogICAgICJwdWJsaWMiOiAiLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS1cbk1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRUM5Uk5Bc3VEQ05PNlQ3cUE3WTVGOG9ydzJ0SVdcbnI3clVyNGZmeHZ6VE1yYmtWdGpSL3RydEUwcTArVDB6UThUV0x5STZFWU13Yjk0N2VqMkl0ZmtPeUE9PVxuLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tXG4iCiAgICB9LAogICAgInNjaGVtZSI6ICJlY2RzYS1zaGEyLW5pc3RwMjU2IiwKICAgICJ4LXR1Zi1vbi1jaS1rZXlvd25lciI6ICJAamFjb2JkZXByaWVzdCIKICAgfSwKICAgIjg4NzM3Y2NkYWM3YjQ5Y2MyMzdlOWFhZWFkODFiZTJhNDAyNzhiODg2YTY5M2Q4MTQ5YTE5Y2Y1NDNmMDkzZDMiOiB7CiAgICAia2V5dHlwZSI6ICJlY2RzYSIsCiAgICAia2V5dmFsIjogewogICAgICJwdWJsaWMiOiAiLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS1cbk1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRUJhZ2tza05PcE9UYmV0VFg1Q2Rudk15K0xpV25cbm9uUnJOcnFBSEw0V2dpZWJIN1VpZzdHTGhDM2JrZUEvcWdiOTI2L3ZyOXFoT1BHOUJ1ajJIYXRyUHc9PVxuLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tXG4iCiAgICB9LAogICAgInNjaGVtZSI6ICJlY2RzYS1zaGEyLW5pc3RwMjU2IiwKICAgICJ4LXR1Zi1vbi1jaS1rZXlvd25lciI6ICJAZ3JlZ29zZSIKICAgfSwKICAgIjhiNDk4YTgwYTFiN2FmMTg4YzEwYzlhYmRmNmFhZGU4MWQxNGZhYWZmY2RlMmFiY2Q2MDYzYmFhNjczZWJkMTIiOiB7CiAgICAia2V5dHlwZSI6ICJlY2RzYSIsCiAgICAia2V5dmFsIjogewogICAgICJwdWJsaWMiOiAiLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS1cbk1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRTdJRW9WTndycHJjaFhHaFQ1c0FoU2F4N1NPZDNcbjhkdXVJU2doQ3pmbUhkS0pXU2JWMndKUmFtUmlVVlJ0bUE4M0svcW01Y1QyMFdYTUNUNVFlTS9EM0E9PVxuLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tXG4iCiAgICB9LAogICAgInNjaGVtZSI6ICJlY2RzYS1zaGEyLW5pc3RwMjU2IiwKICAgICJ4LXR1Zi1vbi1jaS1rZXlvd25lciI6ICJAdHJldnJvc2VuIgogICB9LAogICAiYTEwNTEzYTVhYjYxYWNkMGM2YjZmYmUwNTA0ODU2ZWFkMThmM2IxN2M0ZmFiYmUzZmE4NDhjNzlhNWExODdjZiI6IHsKICAgICJrZXl0eXBlIjogImVjZHNhIiwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICItLS0tLUJFR0lOIFBVQkxJQyBLRVktLS0tLVxuTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFQzJ3SjN4c2N5WHhCTHliSjlGVmp3a3lRTWU1M1xuUkhVejc3QWpNTzhNelZhVDh4dzZadkpxZE5aaXl0WXRpZ1dVTGxJTnh3NmZyTnNXSktiL2Y3bEM4QT09XG4tLS0tLUVORCBQVUJMSUMgS0VZLS0tLS1cbiIKICAgIH0sCiAgICAic2NoZW1lIjogImVjZHNhLXNoYTItbmlzdHAyNTYiLAogICAgIngtdHVmLW9uLWNpLWtleW93bmVyIjogIkBrb21tZW5kb3JrYXB0ZW4iCiAgIH0sCiAgICJkNmE4OWUyM2ZiMjI4MDFhMGQxMTg2YmYxYmRkMDA3ZTIyOGY2NWE4YWE5OTY0ZDI0ZDA2Y2I1ZmJiMGNlOTFjIjogewogICAgImtleXR5cGUiOiAiZWNkc2EiLAogICAgImtleXZhbCI6IHsKICAgICAicHVibGljIjogIi0tLS0tQkVHSU4gUFVCTElDIEtFWS0tLS0tXG5NRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVEZE9Sd2NydVczZ3FBZ2FMakgvbk5kR01CNGtRXG5BdkErd0Q2RHlPNFAvd1I4ZWUyY2U4M05aSHExWkFES2h2ZTBybFlLYUt5M0NxeVE1U21sWjM2Wmh3PT1cbi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLVxuIgogICAgfSwKICAgICJzY2hlbWUiOiAiZWNkc2Etc2hhMi1uaXN0cDI1NiIsCiAgICAieC10dWYtb24tY2kta2V5b3duZXIiOiAiQGtydWtvdyIKICAgfSwKICAgImViOGVmZjM3ZjkzYWYyZmFhYmE1MTlmMzQxZGVjZWMzY2VjZDNlZWFmY2FjZTMyOTY2ZGI5NzIzODQyYzhhNjIiOiB7CiAgICAia2V5dHlwZSI6ICJlY2RzYSIsCiAgICAia2V5dmFsIjogewogICAgICJwdWJsaWMiOiAiLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS1cbk1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRU55blZkUW5NOWg3eFU3MUc3UGlKcFFhRGVtdWJcbmtianNqWXdMbFBKVFFWdXhRTzhXZUlwSmY4TUVoNXJmMDF0MmRESXVDc1o1Z1J4K1F2RHYwVXpmc0E9PVxuLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tXG4iCiAgICB9LAogICAgInNjaGVtZSI6ICJlY2RzYS1zaGEyLW5pc3RwMjU2IiwKICAgICJ4LXR1Zi1vbi1jaS1rZXlvd25lciI6ICJAbXBoNCIKICAgfSwKICAgImViOTc5OWI0ODNhZmZhYzlkYTg3ZWY0YzllYTQ2NzkyODQxNWM5NjEzNDllNjA3ZTVlNmU0ODU2NzliMDdmOGYiOiB7CiAgICAia2V5dHlwZSI6ICJlY2RzYSIsCiAgICAia2V5dmFsIjogewogICAgICJwdWJsaWMiOiAiLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS1cbk1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRU5LTmNOY1grZDczbFMxVFJGYjlWbnA4SnZPb2hcbnpZUStpbjQzaUdlbmJHOFJHbzlMLzZGSjJob1JiVlU2eHNrdnl1RXJjZFBiQ2RJNEd4clE1aThoa3c9PVxuLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tXG4iCiAgICB9LAogICAgInNjaGVtZSI6ICJlY2RzYS1zaGEyLW5pc3RwMjU2IiwKICAgICJ4LXR1Zi1vbi1jaS1vbmxpbmUtdXJpIjogImF6dXJla21zOi8vcHJvZHVjdGlvbi10dWYtcm9vdC52YXVsdC5henVyZS5uZXQva2V5cy9PbmxpbmUtS2V5L2FhZjM3NWZkOGVkMjRhY2I5NDlhNWNjMTczNzAwYjA1IgogICB9CiAgfSwKICAicm9sZXMiOiB7CiAgICJyb290IjogewogICAgImtleWlkcyI6IFsKICAgICAiYTEwNTEzYTVhYjYxYWNkMGM2YjZmYmUwNTA0ODU2ZWFkMThmM2IxN2M0ZmFiYmUzZmE4NDhjNzlhNWExODdjZiIsCiAgICAgIjRmNGQxZGQ3NWYyZDdmMzg2MGUzYTA2OGQ3YmVkOTBkZWM1ZjBmYWFmY2JlMWFjZTdmYjdkOTVkMjllMDcyMjgiLAogICAgICI4ODczN2NjZGFjN2I0OWNjMjM3ZTlhYWVhZDgxYmUyYTQwMjc4Yjg4NmE2OTNkODE0OWExOWNmNTQzZjA5M2QzIiwKICAgICAiNWUwMWM5YTBiMjY0MWE4OTY1YTRhNzRlN2RmMGJjN2IyZDgyNzhhMmMzY2EwY2Y3YTNmMmY3ODNkM2M2OTgwMCIsCiAgICAgImQ2YTg5ZTIzZmIyMjgwMWEwZDExODZiZjFiZGQwMDdlMjI4ZjY1YThhYTk5NjRkMjRkMDZjYjVmYmIwY2U5MWMiLAogICAgICJlYjhlZmYzN2Y5M2FmMmZhYWJhNTE5ZjM0MWRlY2VjM2NlY2QzZWVhZmNhY2UzMjk2NmRiOTcyMzg0MmM4YTYyIiwKICAgICAiOGI0OThhODBhMWI3YWYxODhjMTBjOWFiZGY2YWFkZTgxZDE0ZmFhZmZjZGUyYWJjZDYwNjNiYWE2NzNlYmQxMiIsCiAgICAgIjUzOWRkZTQ0MDE0Yzg1MGZlNmVlYjhiMjk5ZWI3ZGFlMmUxZjRiZjgzNDU0Yjk0OWU5OGFhNzM1NDJjZGM2NWEiCiAgICBdLAogICAgInRocmVzaG9sZCI6IDMKICAgfSwKICAgInNuYXBzaG90IjogewogICAgImtleWlkcyI6IFsKICAgICAiZWI5Nzk5YjQ4M2FmZmFjOWRhODdlZjRjOWVhNDY3OTI4NDE1Yzk2MTM0OWU2MDdlNWU2ZTQ4NTY3OWIwN2Y4ZiIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMSwKICAgICJ4LXR1Zi1vbi1jaS1leHBpcnktcGVyaW9kIjogMjEsCiAgICAieC10dWYtb24tY2ktc2lnbmluZy1wZXJpb2QiOiA3CiAgIH0sCiAgICJ0YXJnZXRzIjogewogICAgImtleWlkcyI6IFsKICAgICAiYTEwNTEzYTVhYjYxYWNkMGM2YjZmYmUwNTA0ODU2ZWFkMThmM2IxN2M0ZmFiYmUzZmE4NDhjNzlhNWExODdjZiIsCiAgICAgIjRmNGQxZGQ3NWYyZDdmMzg2MGUzYTA2OGQ3YmVkOTBkZWM1ZjBmYWFmY2JlMWFjZTdmYjdkOTVkMjllMDcyMjgiLAogICAgICI4ODczN2NjZGFjN2I0OWNjMjM3ZTlhYWVhZDgxYmUyYTQwMjc4Yjg4NmE2OTNkODE0OWExOWNmNTQzZjA5M2QzIiwKICAgICAiNWUwMWM5YTBiMjY0MWE4OTY1YTRhNzRlN2RmMGJjN2IyZDgyNzhhMmMzY2EwY2Y3YTNmMmY3ODNkM2M2OTgwMCIsCiAgICAgImQ2YTg5ZTIzZmIyMjgwMWEwZDExODZiZjFiZGQwMDdlMjI4ZjY1YThhYTk5NjRkMjRkMDZjYjVmYmIwY2U5MWMiLAogICAgICJlYjhlZmYzN2Y5M2FmMmZhYWJhNTE5ZjM0MWRlY2VjM2NlY2QzZWVhZmNhY2UzMjk2NmRiOTcyMzg0MmM4YTYyIiwKICAgICAiOGI0OThhODBhMWI3YWYxODhjMTBjOWFiZGY2YWFkZTgxZDE0ZmFhZmZjZGUyYWJjZDYwNjNiYWE2NzNlYmQxMiIsCiAgICAgIjUzOWRkZTQ0MDE0Yzg1MGZlNmVlYjhiMjk5ZWI3ZGFlMmUxZjRiZjgzNDU0Yjk0OWU5OGFhNzM1NDJjZGM2NWEiCiAgICBdLAogICAgInRocmVzaG9sZCI6IDMKICAgfSwKICAgInRpbWVzdGFtcCI6IHsKICAgICJrZXlpZHMiOiBbCiAgICAgImViOTc5OWI0ODNhZmZhYzlkYTg3ZWY0YzllYTQ2NzkyODQxNWM5NjEzNDllNjA3ZTVlNmU0ODU2NzliMDdmOGYiCiAgICBdLAogICAgInRocmVzaG9sZCI6IDEsCiAgICAieC10dWYtb24tY2ktZXhwaXJ5LXBlcmlvZCI6IDcsCiAgICAieC10dWYtb24tY2ktc2lnbmluZy1wZXJpb2QiOiA2CiAgIH0KICB9LAogICJzcGVjX3ZlcnNpb24iOiAiMS4wLjMxIiwKICAidmVyc2lvbiI6IDIsCiAgIngtdHVmLW9uLWNpLWV4cGlyeS1wZXJpb2QiOiAyNDAsCiAgIngtdHVmLW9uLWNpLXNpZ25pbmctcGVyaW9kIjogNjAKIH0KfQ==")
	if err != nil {
		return nil, err
	}
	opts := tuf.Options{
		RepositoryBaseURL: "https://tuf-repo.github.com",
		Root:              out,
	}

	tufClient, err := tuf.New(&opts)
	if err != nil {
		return nil, fmt.Errorf("initializing tuf: %w", err)
	}
	targetBytes, err := tufClient.GetTarget("trusted_root.json")
	if err != nil {
		return nil, fmt.Errorf("error getting targets: %w", err)
	}
	trustedRoot, err := root.NewTrustedRootFromJSON(targetBytes)
	if err != nil {
		return nil, fmt.Errorf("error creating trusted root: %w", err)
	}

	return trustedRoot, nil
}

func verifyBundles(bundles []*Bundle, desc *v1.Descriptor, trustedRoot *root.TrustedRoot, policy verify.PolicyBuilder, verifierOpts []verify.VerifierOption) ([]VerificationResult, error) {
	verifier, err := verify.NewSignedEntityVerifier(trustedRoot, verifierOpts...)
	if err != nil {
		return nil, err
	}

	verificationResults := make([]VerificationResult, 0)
	for _, bundle := range bundles {
		result, err := verifier.Verify(bundle.ProtoBundle, policy)
		if err == nil {
			verificationResults = append(verificationResults, VerificationResult{Bundle: bundle, Result: result, Desc: desc})
		} else {
			panic(err)
		}
	}

	return verificationResults, nil
}
