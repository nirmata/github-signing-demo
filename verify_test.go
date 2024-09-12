package main

import (
	"testing"
)

func Test_Verify(t *testing.T) {
	opts := VerificationOptions{}
	image := "ghcr.io/nirmata/github-signing-demo:latest"
	predicateType := "https://in-toto.io/provenance/v0.1"
	limit := 100
	oidcIssuer := "https://token.actions.githubusercontent.com"
	subject := "https://github.com/nirmata/github-signing-demo/.github/workflows/build-attested-image.yaml@refs/heads/main"
	opts.PredicateType = &predicateType
	opts.Limit = &limit
	opts.OIDCIssuer = &oidcIssuer
	opts.Subject = &subject

	verifysigstore(&image, opts)
}
