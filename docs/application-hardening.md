# Application-aware container hardening

BreachBench now has a deterministic `harden` command. It reads application manifests,
generates a minimal runtime build, and emits the deployment settings required to
enforce hardening. It does not require Gemini credentials.

```sh
go run . harden detect /path/to/application > application.json
# Review the runtime version, entrypoint, port, writable paths and dependencies.
go run . harden /path/to/application --config application.json --output /path/to/bundle
go run . harden build /path/to/bundle
go run . harden verify /path/to/bundle
```

The output directory must be new and outside the source directory. Existing source
and deployment files are never rewritten. Regenerate into a new directory after
changing requirements; bundle hashes reject accidental modification before builds.

## Supported applications

| Profile | Detection | Runtime image | Requirements |
| --- | --- | --- | --- |
| Go | `go.mod` | Distroless static | CGO-free executable; embedded assets; explicit package entry if not `.` |
| Node | `package.json` | Distroless Node | `package-lock.json`; direct JS entrypoint; majors 22/24/26 |
| Next.js | `next` production dependency | Distroless Node, standalone output | `output: 'standalone'`; production build; single-app standalone layout |
| PHP | `composer.json` | Distroless base + PHP-FPM binary, shared libraries and extensions | `composer.lock`; PHP 8.3/8.4/8.5; separate FastCGI frontend |

An ambiguous monorepo, version range, unknown PHP extension or shell-based start
command needs explicit configuration. The tool fails instead of guessing. Composer
platform checks validate required versions and extensions during the build. Native
Node modules may need additional runtime libraries: the smoke test and your full
application test suite must cover those paths. Unsupported runtimes can continue to
use the bundled upstream Container Hardening Work Bench directly.

Node builds execute the manifest's build script when present, then prune development
dependencies. PHP builds install Composer production dependencies and the supported
extensions required by the application and its locked production packages. Build
scripts execute in Docker stages. PHP production ini defaults are preserved with a
small hardening override; FPM forwards only explicitly named environment variables.

## Example requirements

```json
{
  "name": "orders",
  "runtime": "node",
  "version": "24",
  "platform": "linux/arm64",
  "entry": "server.js",
  "port": 3000,
  "healthPath": "/health",
  "build": false,
  "env": {"APP_ENV": "production"},
  "writable": ["/tmp", "/app/cache"],
  "egress": [{"cidr": "10.20.30.40/32", "port": 5432, "protocol": "TCP"}],
  "secrets": [{"name": "orders-db", "key": "password", "env": "DB_PASSWORD"}],
  "memoryMiB": 512,
  "cpuMillis": 1000,
  "pids": 128,
  "tempMiB": 64
}
```

Use the deployment's actual destination addresses. DNS is not automatically allowed;
declare resolver CIDRs and UDP/TCP 53 if needed. There is no speculative parsing of
`.env` credentials or automatic granting of broad network access. Do not put secret
values in this configuration. Provide existing scoped secrets in your deployment;
restrict database/cloud permissions at the provider itself.

## Generated controls and verification

- Minimal final image, numeric non-root UID/GID 65532, direct entrypoint, no build tools.
- Read-only root filesystem, dropped capabilities, no-new-privileges, memory/CPU limits.
- Explicit, bounded ephemeral writable directories. Compose adds noexec/nosuid/nodev
  tmpfs flags and a PID limit; Kubernetes needs node policy for PID limits and cannot
  express those tmpfs flags on emptyDir.
- A pinned Moby seccomp baseline, resolved for amd64/arm64 and cap-drop-ALL, with
  ptrace, process-memory access, mount, namespace switching, BPF, perf, io_uring and
  other unnecessary privileged operations removed. `execve` remains for startup.
- Optional `syscalls` list to narrow the baseline using workload measurements.
  Include startup and all supported workloads. This is not automated tracing and
  cannot prove coverage of untested application paths. Existing argument restrictions
  are preserved; forbidden calls cannot be re-enabled through this list.
- Kubernetes default-deny egress with explicit CIDR/port rules, a same-namespace-only
  ingress rule, ClusterIP Service, and ServiceAccount without token automount or new
  RoleBindings. Install the generated Localhost seccomp profile on each eligible node.
- Compose is deliberately offline (`network_mode: none`). Vanilla Compose does not
  enforce Kubernetes NetworkPolicies; use the Kubernetes manifest for networked apps.

`build` pulls base references for the selected architecture, records registry digests
in `images.lock.json`, builds with `Dockerfile.locked`, and records the immutable local
image ID. Package repositories inside build stages remain mutable; do not interpret
the digest lock as complete bit-reproducibility or signature verification.

`verify` inspects the exported root filesystem for known shells, downloaders, package
managers and setuid/setgid files, then starts the image using the generated settings.
A temporary static probe checks UID/GID, effective and bounding capabilities,
no-new-privileges, seccomp mode, read-only root, network isolation and denied syscalls.
Readiness uses an explicit HTTP path, an FPM FastCGI ping, or a TCP connection.
`verification.json` records results and limitations. It does not claim Kubernetes
CNI enforcement, cloud IAM correctness or full application compatibility.

Known secret filenames and local dependency caches are excluded from the captured
build context; symlinks and special files are rejected. This is not a secret scanner
or a full `.dockerignore` implementation. Review the captured source before publishing.
All writable mounts are empty and ephemeral; they hide existing image contents and
are unsuitable for persistent uploads/databases without a separate storage design.

The tool generates artifacts and runs local checks. It does not modify cluster nodes,
deploy workloads, push images, or change external credential permissions. Hardening
does not remove an RCE or prevent leakage through an allowed HTTP response: patch
the application and runtime independently.

## Dockerfile runtime stage tracing and GitHub scraping

Use `trace` to inspect an existing `Dockerfile` before hardening or to verify whether a
deployment still runs inside its build environment:

```sh
go run . trace /path/to/Dockerfile --format markdown
go run . trace /path/to/Dockerfile --target runtime --build-arg BASE_IMAGE=zendis/static:1.0.0-rc.8-minimal
```

The tracer resolves:
1. **Deployed stage**: `--target` if provided, otherwise the final stage.
2. **`FROM` chain**: stage-to-stage `FROM <stage>` inheritance and `ARG` / `--build-arg` variable expansion down to the external runtime base image.
3. **`ENTRYPOINT` and `CMD`**: stage-chain inheritance (where redefining `ENTRYPOINT` resets an inherited `CMD`) and known external base image defaults.
4. **Executable origin**: `COPY --from` (including transitive multi-stage hops and `RUN --mount=from=...`), distinguishing multi-stage artifact copies into a minimal runtime image from single-stage builds or `FROM build AS runtime` build-environment inheritance.

Use `scrape` to scan popular GitHub repositories for unhardened Dockerfiles:

```sh
go run . scrape --limit 50 --output /path/to/scrape-report
```

This writes `results.json`, `report.md`, `report.html`, and the collected `dockerfiles/*.Dockerfile` corpus.

## Seccomp provenance

The embedded baseline is Moby profiles commit
`4b8214fc4971e06172938a1f1554ccff6647ee80`, licensed under Apache-2.0.
Source: https://github.com/moby/profiles/blob/4b8214fc4971e06172938a1f1554ccff6647ee80/seccomp/default.json
Its license is retained alongside the embedded profile. Updating it requires a
review of the resulting allowlist and rerunning both architecture tests.
