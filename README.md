# Github signing demo

This repository demomstrates using Github's [artifact attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds) feature with Kyverno image verification rules.

## Signing steps

See [workflow](.github/workflows/build-attested-image.yaml)


## Verification steps

1. Create a kind cluster


```sh
kind create cluster
```

2. Install Kyverno with GitHub the `TrustRoot` 

```sh
helm install kyverno kyverno/kyverno -n kyverno --create-namespace --values manifests/values.yaml
```

3. Apply Kyverno policy to the cluster:
   
```bash
kubectl create -f manifests/policy.yaml
```

4. Run the signed image

```sh

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