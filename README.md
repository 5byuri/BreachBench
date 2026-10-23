# BreachBench 
BreachBench runs adversarial security benchmarks against deterministically generated OCI container images

Built on the OCI Community’s [Container Hardening Work Bench](https://gitlab.opencode.de/oci-community/tools/container-hardening-work-bench).

TODO:

Mandatory:

What is a OCI Container/Docker Container?
How does Container Hardening work?

# Defensive Security Capabilities


- [ ] Configuration files
- [ ] Cross Container Communication (IaC) Kubernetes Rules
- [ ] Rego Policy Tools


# Offensive Security Capabilities:


Make sure AI is really only allowed to be attacking this one sandbox, only target, no cheesing - Luca
- [ ] Simulated Benchmarks (Sandbox) - Lars (pwned, or not pwned)
- [ ] Github Bot implementation - Lars (optional)


# FAQ

> Why don't I just use Distroless?
[Distroless does not cover any Application](https://github.com/GoogleContainerTools/distroless#what-images-are-available)
[Other Tradeoffs, such as Maintainability & Shipping are difficult](https://docs.docker.com/dhi/explore/security-concepts/distroless/#addressing-common-tradeoffs)

Made without Agents
