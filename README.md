# Github signing demo

This repository demomstrates using Github's [artifact attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds) feature with Kyverno image verification rules.

## Signing steps

See [workflow](.github/workflows/build-attested-image.yaml)


## Manual verification

Run this program to manually check the attestation:

```sh
go run verify.go --image ghcr.io/nirmata/github-signing-demo:latest --predicate-type "https://slsa.dev/provenance/v1" --subject "https://github.com/nirmata/github-signing-demo/.github/workflows/build-attested-image.yaml@refs/heads/main"
```

You can also use the GitHub CLI:

```sh
gh attestation verify oci://ghcr.io/nirmata/github-signing-demo:latest --repo nirmata/github-signing-demo
```

This should show an output similar to:

```sh
Loaded digest sha256:79c29305a38c0c92657d72c0d14e0521227d02f0fc55eaa9fcc5c7f997efa944 for oci://ghcr.io/nirmata/github-signing-demo:latest
Loaded 1 attestation from GitHub API
✓ Verification succeeded!

sha256:79c29305a38c0c92657d72c0d14e0521227d02f0fc55eaa9fcc5c7f997efa944 was attested by:
REPO                         PREDICATE_TYPE                  WORKFLOW
nirmata/github-signing-demo  https://slsa.dev/provenance/v1  .github/workflows/build-attested-image.yaml@refs/heads/main
```

## In Cluster Verification

1. Create a kind cluster


```sh
kind create cluster
```

2. Install Kyverno  

```sh
helm install kyverno kyverno/kyverno -n kyverno --create-namespace
```

**Note**: to verify a private GitHub repository install the GitHub `TrustRoot`:

```sh
helm install kyverno kyverno/kyverno -n kyverno --create-namespace --values manifests/values.yaml
```

3. Apply Kyverno policy to the cluster:
   
```bash
kubectl create -f manifests/policy.yaml
```

4. Run the signed image

```sh
kubectl run demo --dry-run=server --image  ghcr.io/nirmata/github-signing-demo:latest
```

```sh
pod/demo created (server dry run)
```

5. Run an unsigned image, and verify it is blocked

```sh
kubectl run demo --dry-run=server --image nginx
```

```sh
Error from server: admission webhook "mutate.kyverno.svc-fail" denied the request:

resource Pod/default/demo was blocked due to the following policies

sigstore-image-verification:
  sigstore-image-verification: 'failed to verify image docker.io/nginx:latest: .attestors[0].entries[0].keyless:
    sigstore bundle verification failed: no matching signatures found'

```

