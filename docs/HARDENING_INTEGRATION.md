# Integrating container candidates with verification

The `feat/gemini-container-hardening` branch exposes the Node workflow through the existing Go Cobra CLI:

```bash
go run . harden run --config workload.json --output .breachbench/workload
```

For an image produced by the separate GitHub hardening bot or deb2scratch tooling, supply its original source image, distinct `breachbench/` candidate tag, local build context/Dockerfile, non-root identity, resource limits and representative tests. Do not assume a generated scratch Dockerfile is functionally correct or fixes the upstream runtime.

Required workload test categories are `foreground`, `background` and `uncommon`. Security tests must assert specific denial results. When loading a reviewed seccomp profile, keep its review sidecar and five source traces available so the image/profile/trace identity checks can validate them.

The seven tools are individually callable as `go run . harden inspect_container --config workload.json`, and so forth. A candidate passes functionality and enforcement before `compare_results` can mark it eligible for review. Original source image IDs and local backup tags remain recorded; no candidate is promoted automatically.

The networking and credentials conformance runner creates its own kind/Calico cluster; it does not use the user's current Kubernetes context. Its reports establish enforcement for those controlled manifests. Application-specific generated deployment manifests need the same tests against their actual selected dependencies and CNI before their enforcement can be asserted.

The separate `feat/harden-pr-bot` branch was fetched and inspected but has not been merged into this branch. Integrators can consume this CLI contract without rewriting the scanner, runtime controls or acceptance gates.
