# Gemini container hardening

This is a defensive workflow on `feat/gemini-container-hardening`. Node 22+ provides CLI tools without npm dependencies. The existing Go CLI remains separate. Run commands from the repository root on a disposable Linux/WSL2 runner with Docker Engine, Go (as required by the work-bench's go.mod), Trivy and SlimToolkit installed. Image builds, Slim and tests execute application code; use an isolated runner, not a production Docker host.

## Windows / Ubuntu WSL toolchain

The current demo uses **Gemini inside Antigravity** to inspect this repository and invoke the CLI tools. Follow [the Antigravity handoff](ANTIGRAVITY.md). The direct Gemini API integration is optional and currently blocked by the supplied billing account's monthly spending cap; it is not needed for these commands. Antigravity access does not establish Gemini API quota or credit eligibility.

Docker Desktop must use Linux containers with Ubuntu WSL integration enabled. From PowerShell in this repository:

```powershell
node hardening/setup-tools.mjs
wsl -d Ubuntu -- bash hardening/setup-tools.sh
wsl -d Ubuntu -- bash hardening/wsl-run.sh versions
wsl -d Ubuntu -- bash hardening/wsl-run.sh run hardening/demo/config.json .breachbench/live-demo
# Separate workload-traced Slim candidate, tested independently:
wsl -d Ubuntu -- bash hardening/wsl-run.sh slim-demo
# Multi-phase strace capture & automated candidate validation (keeps reviewed: false):
wsl -d Ubuntu -- bash hardening/wsl-run.sh trace-demo
wsl -d Ubuntu -- bash hardening/wsl-run.sh lsm-check
# Run workflow against an already-reviewed profile (does NOT auto-mark reviewed: true):
wsl -d Ubuntu -- bash hardening/wsl-run.sh seccomp-demo
```

The downloader selects official Go 1.27.3, Trivy 0.76.1, Linux Node 24.11.1 and the SlimToolkit 1.40.11 release asset. It verifies upstream SHA256 values where provided. That Slim asset has no upstream digest; the local manifest records its actual SHA256 and explicitly marks it unverified against an upstream checksum. The executable's own `--version` is printed separately because release assets can identify a different internal build. Downloads and the provenance manifest live in `.breachbench/tools/downloads`; executables install under Ubuntu's `${XDG_DATA_HOME:-$HOME/.local/share}/breachbench/tools`. The wrapper sets PATH only for its process and uses Linux temporary directories for Go/Trivy caches. Existing system installations and shell startup files are unchanged.

The Slim workload exercises all demo routes and its background job while tracing; explicit includes retain Python's standard library, the application and certificate bundle for uncommon paths. This favors correctness over maximal size savings. The wrapper chooses Docker's server API version explicitly for Slim to support newer engines. No Gemini key is required for these deterministic runs.

The demo also exercises `ctypes` during tracing so its syscall probe retains `libffi`. Slim removes unused build-time `GPG_KEY`/`PYTHON_SHA256` variables and disables private certificate-key retention. Debian release markers and dpkg metadata are retained for scanner visibility. Those metadata can still describe removed packages: compare with the baseline and inspect affected files before claiming that any vulnerability was eliminated. The report rejects reduced OS scanner visibility.

## Gemini account and API key

1. Sign in to [Google AI Studio](https://aistudio.google.com/apikey), create/select your Google Cloud project, and create an API key. Account creation, terms and billing need the account owner. Do not paste the key into chat or commit it.
2. Store the key in your shell/secret manager. PowerShell: `$env:GEMINI_API_KEY = '<your key>'`; Bash: `export GEMINI_API_KEY='<your key>'`.
3. Set `GEMINI_MODEL` to a function-calling model available to your project. No model is hard-coded because availability and quotas vary. For example, use the model identifier shown in AI Studio.
4. Optional: set `GEMINI_SAFETY_OFF=true` to request `OFF` for the four adjustable generateContent content categories. This does not remove model-level/core protections or provider policies. Errors and blocks remain errors; the workflow does not retry around them.

The integration uses the [generateContent REST API](https://ai.google.dev/api/generate-content) with function declarations and responses. See [API key setup](https://ai.google.dev/gemini-api/docs/api-key) and [safety settings](https://ai.google.dev/gemini-api/docs/safety-settings). `.env.example` documents names; files are not automatically loaded. Credentials are stripped from child process environments, and raw image environment variables and Trivy secret matches are omitted from reports. Package names, vulnerability findings and test outcomes are sent to Gemini when you choose `gemini` mode.

PowerShell environment variables are not automatically forwarded into WSL. If running Gemini through `wsl-run.sh`, either set them inside Ubuntu or add their **names** to WSLENV before launching:

```powershell
$env:WSLENV = (($env:WSLENV, 'GEMINI_API_KEY', 'GEMINI_MODEL', 'GEMINI_SAFETY_OFF') | Where-Object { $_ }) -join ':'
wsl -d Ubuntu -- bash hardening/wsl-run.sh gemini hardening/demo/config.json .breachbench/gemini-demo
```

No key is passed as a command-line argument or written by the launcher. Gemini requests and billing/quotas are not tested until you configure your account.

To test access with one small generation request before running Docker tools:

```powershell
wsl -d Ubuntu -- bash hardening/wsl-run.sh gemini-check hardening/demo/config.json
```

For model discovery and detailed quota troubleshooting, run directly in the PowerShell session containing your key:

```powershell
node hardening/gemini-diagnose.mjs
```

This sends metadata-list requests and, only when the selected model appears in the list, one small generation request. It never executes Docker tools, changes models automatically, or retries a failing generation. Provider descriptions are included with the configured API key and recognizable Google API keys redacted. It does not inspect or modify the Cloud Billing account. Model-list success alone is not proof of inference access or that hackathon credits apply.

On HTTP 429, diagnostics expose only selected quota identifiers, limits and retry timing, with credential redaction; the raw response is omitted. Check the **same project as the API key** in AI Studio's Usage/Rate limits and Billing pages. A zero quota, exhausted daily quota, short-term request limit and billing/spend restriction need different remedies; changing the API key inside the same project does not create new quota. Do not assume hackathon Google Cloud credits are eligible for Gemini API. If the supplied credits require Vertex AI, this integration needs a separate endpoint/authentication backend before using them.

## Run the demo

```bash
git submodule update --init --recursive
docker build -f hardening/demo/Containerfile -t breachbench/demo:baseline hardening/demo
# Docker-only readiness check (no Gemini key, Go, Trivy or Slim needed):
node hardening/docker-check.mjs
node --test hardening/test/*.test.mjs
node hardening/cli.mjs run hardening/demo/config.json
# Same configured tools, selected by Gemini, with host-enforced ordering:
node hardening/cli.mjs gemini hardening/demo/config.json
```

Each tool can also run individually: `node hardening/cli.mjs inspect_container hardening/demo/config.json`. An optional final argument selects an evidence directory (default `.breachbench`). Use a separate directory per workload and never run two workflows concurrently in one directory. Configuration and test commands are operator-trusted executable inputs. Gemini cannot change them or supply command arguments. CLI failure is nonzero; missing dependencies or stale/incomplete evidence never count as success.

Order: `inspect_container` → `scan_image` → `propose_hardening` → `build_candidate` → `test_application` → `verify_hardening` → `compare_results`.

Use `verify` instead of `run` to repeat functionality, enforcement and comparison against an already built candidate. Configuration, custom seccomp files, workload scripts and Dockerfile contents participate in the evidence fingerprint. Add other external test inputs to `evidenceFiles` in the config. Tool failure diagnostics are written only to the ignored local `.breachbench/tool-error.log`; review locally because tool stderr can contain workload data.

Inspection runs `go run . inspect --tag IMAGE --output ...` inside the actual in-repository **Container Hardening Work Bench**, pinned to `21f38fed9c32a39a694ba0fec32b933bfc0dbcd0`. It extracts filesystem layers for local review. Trivy scans vulnerabilities, secrets, image configuration, Dockerfiles and deployment manifests in the configured context, producing normalized component/fix findings. Keep all deployment manifests inside that context. The work-bench's usage document is older than its current CLI; this wrapper follows `cmd/inspect.go`.

## Image changes versus deployment controls

The candidate Containerfile references the inspected immutable image ID and adds a non-root USER. Optional Slim removes files; it does not patch an old PHP runtime. Add a `slim` object to the config with an `execFile` (Slim's representative in-container workload script) and `includePaths` (files needed for uncommon/recovery paths). The integration runs `slim build --continue-after=exec` and retains both candidate and candidate-slim tags. Both the original and selected candidate run the configured foreground, background and uncommon tests. Size reduction alone never establishes correctness. [Slim reference](https://github.com/slimtoolkit/slim).

Runtime Docker controls drop all capabilities, disable privilege escalation, use non-root identity, a read-only root and scoped tmpfs directories, enforce resource limits, and omit host mounts, Docker socket and privileged mode. No capability is added automatically. Demonstrate a requirement with failing tests and review a narrowly scoped exception in code. Writable volumes are ephemeral; stateful apps need a separately reviewed persistence design.

Docker tests use `--network none`, which deliberately permits no external dependencies. The demo tests connectivity within the container and checks that outbound attempts return a local routing denial (a timeout is not accepted). For apps needing DNS, APIs or databases, the generated Kubernetes NetworkPolicy supports explicit `egress` entries with `to` selectors/ipBlocks and `ports`; it also defaults to denying ingress, so configure required ingress explicitly. DNS requires both UDP/TCP 53 and a destination selector scoped to the DNS namespace/pods. Standard NetworkPolicy does not allow API hostnames; use stable destination CIDRs or a CNI supporting FQDN policies. Policy files are proposals and are never automatically applied.

`pod-controls.json` is a fragment for a deployment, not a standalone Pod. Add the `app: breachbench-candidate` Pod label to match the policy. Set service-account automount false, inject narrowly scoped short-lived credentials at runtime, and rotate any secret found in image history. Kubernetes PID limits require kubelet/runtime configuration. Verify allowed and denied traffic using the actual CNI, including DNS and IPv6 as applicable; a policy object alone does not establish enforcement. The report always labels cluster enforcement unverified. The Docker acceptance result concerns only the Docker test environment.

## Syscalls and AppArmor/SELinux

Docker's default seccomp applies unless a custom profile is configured. To derive a candidate allowlist from a single trace file or run the full multi-phase capture (`startup`, `foreground`, `background`, `uncommon`, `shutdown`) separated from enforcement testing:

```bash
node hardening/profiles.mjs workload.strace .breachbench/seccomp.candidate.json
node hardening/profiles.mjs trace hardening/demo/config.json .breachbench/seccomp-demo
node hardening/profiles.mjs validate .breachbench/seccomp-demo/seccomp.candidate.json
# Only after explicit operator permission review of traces and justifications:
node hardening/profiles.mjs review .breachbench/seccomp-demo/seccomp.candidate.json .breachbench/seccomp-demo/seccomp.reviewed.json --review-type manual-permission-review --review-evidence .breachbench/seccomp-demo/syscall-observation.json hardening/demo/config.json .breachbench/seccomp-demo/config.json
node hardening/profiles.mjs lsm-check .breachbench/seccomp-demo/lsm-support.json
```

`profiles.mjs trace` verifies the pinned in-repo **Container Hardening Work Bench** (`inspect` + `readelf -d` shared-library analysis), binding the extracted filesystem to the exact immutable image ID (`<filesystem>.meta.json`) and invalidating the cache whenever the image ID changes. It runs the workload under user-local `strace -f` across all five phases without mixing negative probes into the observation phase, and writes `.breachbench/seccomp-demo/seccomp.candidate.json` (`defaultAction: "SCMP_ACT_ERRNO"`) alongside `.breachbench/seccomp-demo/seccomp.candidate.json.review.json`. Automated structural/policy validation (`profiles.mjs validate`) checks phase completeness, justifications for all non-observed syscalls, and exclusion of forbidden/probe syscalls (`getppid`, `getpgid`, `ptrace`, `mount`, `bpf`, `capset`, `setuid`, etc.), recording `automatedValidation` while keeping `reviewed: false` and `reviewType: "automated-validation-only"`. `wsl-run.sh seccomp-demo` runs `trace`, `validate`, and `cli.mjs run` against an already-reviewed profile and **never** marks a candidate `reviewed: true` automatically. `loadConfig` rejects any profile whose `.review.json` sidecar has `reviewed: false`, an automated `reviewType`, or missing `reviewEvidence`.

For AppArmor, run `aa-genprof`/`aa-logprof` on a compatible Linux host while exercising the same representative workloads, review the resulting filesystem/network/exec permissions, load it using `apparmor_parser`, switch to enforce, and configure `apparmorProfile` with its loaded name. For SELinux, collect AVCs in a dedicated test domain, review candidate `audit2allow` rules, load the reviewed module and set `selinuxType`. Both `profiles.mjs lsm-check` and `verify_hardening` explicitly inspect kernel/filesystem state and `docker info --format '{{json .SecurityOptions}}'`: on this WSL2/Docker Desktop host (`6.6.87.2-microsoft-standard-WSL2`, `/sys/module/apparmor/parameters/enabled = N`, `/sys/fs/selinux/enforce` absent, Docker `SecurityOptions = ["name=seccomp,profile=builtin","name=cgroupns"]`), AppArmor and SELinux remain **unverified** (`status: "unverified-on-host"`, `verified: false`, `tested: false`, `enforced: false`, `overallStatus: "partial-seccomp-only-apparmor-selinux-unverified"`), and `verify_hardening` rejects any config requesting `apparmorProfile` or `selinuxType` when host/daemon support is absent.

## Verification, review and rollback

Tests are host argv arrays with `{container}` and `{image}` substitutions. Provide positive tests with exit-zero assertions and negative tests that assert the specific expected denial, rather than treating any failed command as a pass. The demo verifies identity, EROFS writes, writable tmpfs, zero effective/permitted/bounding capabilities, NoNewPrivs, explicit syscall EPERM, network routing denial and configured resource limits. Add stress tests for actual OOM/CPU/PID enforcement if needed; the demo checks resource configuration, not saturation behavior. Minimal images may lack Python/shell; supply application-specific probe binaries or external test harnesses and retain them only in test variants as appropriate.

Reports include image IDs/sizes, findings, functionality and enforcement evidence, security regressions and remaining risks. `eligible-for-review` requires all configured tests plus all mandatory categories; it does not deploy/promote the candidate or assert Kubernetes enforcement. An interrupted/repeated stage invalidates later evidence. Original tags and deployments remain intact. Roll back using the original image ID recorded in `proposal.json`; preserve deployment manifests and their previous secret references separately.

Hardening limits exposure. It neither fixes a vulnerable PHP/runtime version nor completely prevents exploitation. Upgrade the runtime and rescan, review exclusions and credentials, and rerun workloads and controls whenever the app or deployment changes.
