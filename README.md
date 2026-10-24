# BreachBench 

<p align="center">
    <picture>
      <source srcset="docs/logo.svg">
      <img src="docs/logo.svg" width="240" height="80">
  </picture>
</p>

BreachBench runs adversarial security benchmarks against deterministically generated OCI container images

Built on the OCI Community’s [Container Hardening Work Bench](https://gitlab.opencode.de/oci-community/tools/container-hardening-work-bench).

## Application hardening

Run the isolated before/after demo with `go run . harden demo /absolute/path/to/new-results`.
It saves an HTML report and JSON evidence; see [the demo guide](docs/hardening-demo.md).

`go run . harden /path/to/app` generates minimal images and runtime policies for
Go, Node/Next.js and PHP-FPM. Use `harden detect`, `harden build` and `harden verify`
to review requirements, build the image, and check runtime restrictions.

See [application hardening](docs/application-hardening.md) for configuration,
Kubernetes/Compose deployment, and the limits of automatic inference.

## Harden an existing application image

The supplied-image workflow preserves application/runtime versions, removes
selected unnecessary tool entrypoints, and compares application checks under a
non-root/read-only runtime. It does not patch vulnerabilities or require Node in
the image for its probes.

```sh
go build -o bin/breachbench .
demo_parent=$(mktemp -d /tmp/breachbench-image.XXXXXX)
./bin/breachbench harden auto \
  --image local/react2shell:unhardened \
  --target "local/react2shell:hardened-$(basename "$demo_parent")" \
  --checks fixtures/react2shell/workload.json \
  --policy fixtures/react2shell/policy.json --artifacts "$demo_parent/results"
cat "$demo_parent/results/comparison.md"
```

This starts from an existing local image and uses deterministic tools without an
API key. `harden agent` uses Argon for bounded tool selection; existing macOS
Keychain configuration is reused automatically. Runtime controls require the
generated `compose.json`, not just the candidate image. No remote exploit is
attempted, and hardening does not fix React2Shell.

See [image hardening](docs/image-hardening.md) for workload/policy formats,
credentials, evidence and limitations. The imported commands are also available
under `harden image`; native `harden APP`, `harden build`, `harden verify` and
`harden demo` remain unchanged. The imported implementation retains its
[L3montree MIT notice](internal/imagehardening/LICENSE.md).

`harden auto` and `harden agent` show progress and a readable before/after table
on a terminal. Use `--format human` to force that view or `--format json` for
automation; `report.json` is always retained. See the
[browser demo](docs/react2shell-browser-demo.md) for The British Bank, a fictional
GBP banking sandbox on the real, intentionally vulnerable Next.js application.
It uses dummy balances and a transfer-preview Server Action, with no real money,
login, customer data or payment integration.

![The fictional British Bank demo after hardening](docs/british-bank-demo.jpg)

## Credentials

Keep API keys in the existing macOS Keychain configuration or environment, never
in source files, command arguments, reports or Git commits. `.env` files, built
binaries and raw demo-run artifacts are ignored. Rotate any key shared in chat
or logs; removing it from a file does not revoke it.

The repository's `.gitleaks.toml` extends the standard rules with a check for
AQ-prefixed credentials. Before publishing, scan both files and all Git refs:

```sh
gitleaks dir --redact=100
gitleaks git --redact=100 --log-opts="--all --full-history --root --diff-merges=first-parent"
```

## Dockerfile runtime stage tracing & GitHub scraper

`go run . trace [path/to/Dockerfile]` (or `go run . harden trace`) implements automated
4-step Dockerfile runtime stage tracing:
1. Identifies the deployed stage (`--target` or the last stage by default).
2. Follows the `FROM` inheritance chain across named stages and `ARG` / `--build-arg` values back to the external runtime base image.
3. Resolves effective `ENTRYPOINT` and `CMD` across the `FROM` chain and known base image defaults.
4. Traces the startup executable's origin (`COPY --from=<stage>`, transitive multi-stage copies, build context copies, or in-stage builds) so an executable built in Go/Rust/Node and copied into a minimal/static image is distinguished from a container that inherits and runs inside its build environment (`FROM build AS runtime` or single-stage toolchain builds).

`go run . scrape --output /path/to/scrape-results` queries GitHub's most popular repositories,
fetches and traces their Dockerfiles, and generates JSON, Markdown, and HTML reports highlighting
unhardened single-stage and build-environment-inheriting Dockerfiles.

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
