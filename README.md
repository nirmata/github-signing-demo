# Github signing demo

This repository contains a demo to verify Github's Artifact attestation using Kyverno image verification rules

## Signing steps

Use githubs `actions/attest` workflow to sign the image and attach a sample shit provenance report to it
## Verification steps

Clone Kyverno repository:
```bash
git clone https://github.com/kyverno/kyverno.git
cd kyverno
```

1. Create a kind cluster:
```bash
make kind-create-cluster
```

2. Copy `manifests/values.yaml` and add it to kyverno`s `charts/kyverno/values.yaml` file

3. Install kyverno helm chart
```bash
make kind-deploy-kyverno
```

4. Apply `manifests/policy.yaml` to the cluster:
```bash
kubectl create -f manifests/policy.yaml
```

5. 4. Crate `manifests/pod.yaml` to the cluster:
```bash
kubectl create -f manifests/pod.yaml
```