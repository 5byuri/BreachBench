# Supplied-image hardening

This workflow starts from an existing local Linux application image. It does not
replace BreachBench's native application-bundle commands in
[application hardening](application-hardening.md) or the
[native training demo](hardening-demo.md).

```sh
go build -o bin/breachbench .

# Optional old-CLI compatibility executable.
go build -o bin/container-hardening-agent ./cmd/container-hardening-agent
```

All imported actions are available as `./bin/breachbench harden image ACTION`.
The non-conflicting `auto`, `agent`, `static`, `gemini`, `pentest`, `tool-demo`, `inspect`,
`scan`, `config`, `minify`, `run` and `compare` also work directly under `harden`.
Use `harden image build`, `harden image verify` and `harden image demo` for the
imported versions: direct `harden build/verify/demo` remain the native commands.
The compatibility binary retains the old `harden ACTION` syntax.
The old standalone root build/Devguard-scanner entrypoint is not imported;
`harden scan` remains the separate Trivy wrapper.

The generic `auto` and `agent` commands use a compact progress display and
before/after table on a terminal. Add `--format human` to force it, or
`--format json` for machine-readable stdout. The default `--format auto` keeps
JSON when stdout is piped or redirected. `report.json` is always saved as JSON,
regardless of terminal format. Other imported commands retain their JSON output.
Diagnostics go to stderr; commands support `-h` and `--timeout`.
Generic hardening needs Docker and a local Go toolchain. Trivy
and SlimToolkit are needed only for their separate commands, not the default
workflow. The imported implementation's
[MIT notice](../internal/imagehardening/LICENSE.md) preserves the original
L3montree attribution.

## Static-only hardening

Use this when the target application must not execute. It inspects an existing
local Linux image, reads filesystem metadata from a stopped-container export,
and repacks selected tool entrypoints without building or running image code.
Neither application checks, containment probes, Slim profiling nor foreign-binary
`ldd` execution are used. No archive is extracted onto the host.

```sh
static_parent=$(mktemp -d /tmp/breachbench-static.XXXXXX)
./bin/breachbench harden static \
  --image local/graphify:baseline-92741d1 \
  --target "local/graphify:static-$(basename "$static_parent")" \
  --artifacts "$static_parent/results" --format human
```

`static` defaults to Argon (`gemini-4-argon`), using the existing credential
configuration below. It calls `inspect_image_static`, `remove_unneeded_tools`
and `apply_static_hardening` in order. The bounded local tools do the real work;
the AI cannot execute arbitrary commands, remove application/library files,
upgrade components or weaken the runtime policy. `--mode tools` applies all
eligible fixed tool-entrypoint removals without a model. Both modes create only
a candidate, with `application_tested:false` and `compatibility:"unverified"`.

No `--checks` is needed. Optional `--policy policy.json` uses the same runtime
policy format below. A statically resolved existing non-root UID:GID is preserved;
root/empty USER selects `65532:65532`, which can break ownership-sensitive apps.
Unresolvable identities require an explicit numeric `policy.user`, never a guess.
Shell startup scripts and enabled health checks conservatively retain required
tools. This is not proof that remaining removals are unnecessary: dynamic
subprocess calls, plugins and optional features may still require them. Only the
fixed tool entrypoints are pruned, not entire packages, Python modules or all
vulnerable components. App/runtime bytes and versions are retained unchanged.

The default is read-only root, no additional writable directories, bounded
ephemeral `/tmp`, dropped capabilities, no-new-privileges, Docker's default
seccomp, resource limits and `network:none`. These are restrictive assumptions,
not inferred needs. Explicit `internal` permits peers on one isolated bridge;
`bridge` permits external egress. There is no inferred service-direction policy,
automatic Compose-stack analysis, persistent-data migration or automatic
credential removal. Writable-path aliases fail closed rather than being probed.

Outputs are `report.json`, `plan.json`, and `compose.json` in a new private
directory. The source image is preserved. The model sees filtered static facts,
not raw environment values, command arguments, application source or raw files.
Image defaults, including embedded credentials, remain in the candidate; review
those separately. Runtime controls require the deployment configuration, not just
the new image. The report separates actual entry removal from unknown runtime
behavior. No runtime denial, compatibility or exploit-resistance claim is made.
Use the existing `auto`/`agent` workflow with meaningful checks if runtime
validation is later wanted.

### Recorded Graphify static run

On 2026-10-25, `static --mode argon` completed against the existing local
Linux/arm64 Graphify image built from upstream commit
`92741d162b2094ffc2fed58cfbd8ee823e9da62c` (v8 Dockerfile). Argon called the three
ordered tools and removed six actual entries: `/usr/bin/sh`, `bash`, `dash`,
`apt`, `apt-get`, and `dpkg` (all under `/usr/bin`). The existing primary
UID:GID remained `10001:10001`; the original image ID was unchanged. Retained
file bytes were copied, not patched. Python and its package libraries, including
`pip`, were not removed or upgraded.

The candidate is `local/graphify:static-argon-nf5rc9`, ID
`sha256:54b6f229d2297a6356297d7f1ccec64f254530207054a35ce5c729431df73fa5`.
The [recorded report](../demo/evidence/graphify-static-2026-10-25/report.json),
[plan](../demo/evidence/graphify-static-2026-10-25/plan.json), and
[deployment](../demo/evidence/graphify-static-2026-10-25/compose.json) contain
filtered findings only. Neither source nor candidate application was started
by this static run. Application compatibility, optional Graphify features,
shell-access denial and exploit resistance remain unverified. Network denial
and read-only controls are deployment settings, not tested results.

## Harden an existing image

Use meaningful HTTP or finite batch checks, a new target tag and a new artifact
directory. To build the intentionally vulnerable local Next.js fixture from the
repository root (never publish or deploy it), use:

```sh
docker build -f fixtures/react2shell/Containerfile \
  -t local/react2shell:unhardened fixtures/react2shell
```

Then run:

```sh
demo_parent=$(mktemp -d /tmp/breachbench-image.XXXXXX)
./bin/breachbench harden auto \
  --image local/react2shell:unhardened \
  --target "local/react2shell:hardened-$(basename "$demo_parent")" \
  --checks fixtures/react2shell/workload.json \
  --policy fixtures/react2shell/policy.json --artifacts "$demo_parent/results"
cat "$demo_parent/results/comparison.md"
```

`auto` defaults to `--mode tools`, with no API key or Slim requirement. `agent`
defaults to `--mode argon`; either command accepts an explicit `--mode`. For your
own image, supply its local reference and application-specific checks/policy.
An image alone cannot establish all of an application's runtime requirements.

The CLI pins the source locally, validates the baseline, filters selected entries
from a Docker filesystem export stream, repacks/loads a candidate, and checks the
same workload under runtime restrictions. Retained file bytes and image config,
including ENTRYPOINT/CMD, are preserved except for the selected non-root USER.
It does not edit application code or upgrade runtimes/dependencies. This is
selected shell/package/download-tool entrypoint pruning, not complete unused-file
or dependency discovery. Slim is not used in the generic path.

The bounded loop makes at most three attempts, retaining more tools after
compatibility failures. Required shells may remain. The model cannot weaken
checks or controls to make a candidate pass. Failed/inconclusive checks or unmet
runtime constraints return nonzero without publishing the target; the original
image is preserved. Run images only on an isolated Docker host without production
access.

### Workload JSON

For a long-running HTTP service, `workload.json` keeps the real image command:

```json
{
  "mode": "http",
  "port": 3000,
  "startup_timeout_seconds": 60,
  "http_checks": [
    {"path": "/health", "status": 200, "body_contains": "healthy"}
  ]
}
```

A static Go helper is cross-compiled for the image architecture and bound
read-only into disposable containers. The image needs no shell, Node, Python or
package manager for instrumentation. HTTP requests target only `127.0.0.1` inside
the container: no host test ports, external HTTP targets, proxies or redirects.
Evidence contains status codes and response-body hashes, not raw bodies.

For a finite program use `{"mode":"batch"}` to test its original ENTRYPOINT/CMD,
or add `"command":["/app/test","--smoke"]` to override it. An override proves that
command worked, not that the original server starts. Timeouts default to 30
seconds, at most 120. Coverage is limited to the checks you declare; unobserved
does not mean unnecessary. Exercise additional jobs, startup modes and error paths
before relying on a candidate in production.

### Optional runtime policy

```json
{
  "user": "65532:65532",
  "writable_paths": ["/app/cache"],
  "network": "none"
}
```

Pass this file with `--policy policy.json`. By default, an existing non-root
numeric UID:GID is preserved; otherwise `65532:65532` is selected. The candidate
uses read-only root, dropped capabilities, no-new-privileges, Docker's default
seccomp, resource limits and a bounded noexec `/tmp` tmpfs. Declare only narrow
required writable directories; they become additional bounded ephemeral tmpfs
mounts. Protected trees, broad application roots and symlinks into protected trees
are rejected. Image-declared volume paths must match exact writable exceptions.
Existing volume data is not copied or migrated; this is not persistent-storage
orchestration.

Network defaults are `none` for batch and `internal` for HTTP. `internal` creates
an isolated bridge, not an inferred per-service allowlist. Explicit `bridge`
permits external egress and carries no network-containment claim. Baseline and
candidate application checks use the same selected network setting. Automatic
multi-service topology discovery/Compose-stack hardening and Windows images are
unsupported. A supported Linux architecture does not guarantee every application
can satisfy the selected runtime constraints.

### Evidence and deployment

The application baseline preserves the actual image USER and command; it is not
artificially made root. Both sides share resource/capability restrictions for test
isolation, so this is not a reconstruction of production's original privileges.
Separate fixed post-code-execution probes override the command, disable network
access, and measure UID:GID, thirteen listed shell commands, protected writes
under `/`, `/usr`, `/etc`, declared writable paths, and copying/executing a harmless
local native tool under protected root. Missing standard directories are tested
by attempting to create them; absence alone is not a permission-denial result.
Aliases or infrastructure failures remain inconclusive.

This does not download/install packages, exploit a vulnerability, test egress,
or prove that arbitrary runtime code execution is blocked. PHP, Node and Python
can execute code without a shell; writable mounts remain available. Shell
absence is not required when the application genuinely needs a shell.

The new private artifact directory contains `report.json` (attempts and evidence),
`comparison.md`, `compose.json`, and the public static probe. Read-only, tmpfs,
capability and network settings require `compose.json` or equivalent deployment
controls; the image alone cannot enforce them. Image environment defaults remain
present. Raw application output stays local; review evidence before sharing it.
Run-owned temporary containers/networks/tags are cleaned up, but host failure or
process kill can require cleanup.

The [real fixture](../fixtures/react2shell/README.md) and its
[verification record](../fixtures/react2shell/verification-evidence.md) document
the local tools-mode result: homepage/health HTTP 200 before and after; accessible
tested shell commands 6/13 to 0/13; UID 0 to 65532; protected writes allowed to
`EROFS`. Next.js `15.1.0` and the vulnerable RSC implementation remained unchanged.
Ordinary Server Action checks and matching application/runtime hashes were also
recorded. No React2Shell exploit was attempted: this hardening is not its patch.

## Argon and credentials

Argon uses the official `google.golang.org/genai` SDK's Interactions function calls
(`remove_unneeded_tools`), not a generated shell script. It can select only
allowlisted tool entrypoints, not arbitrary Docker options, app edits, dependency
upgrades or external attack targets. Only filtered metadata and fixed results
enter the stateless model conversation (`store:false`), not source, environment
values, command contents or raw application output.

`--model` defaults to `gemini-4-argon`; the API account must have access and quota.
The imported commands do not load `.env`. A Gemini website account alone does not
configure API access. `GEMINI_API_KEY` from the process environment takes
precedence. When it is unset on macOS, BreachBench automatically uses the existing
Keychain generic password for service `container-hardening-work-bench.gemini`,
account `GEMINI_API_KEY`. That identifier is intentionally unchanged for migration:
there is no need to copy or print an existing key. Other platforms use the
environment variable. The key is never stored in repository files or reports.

Only if setting/rotating the Keychain entry is needed, use the hidden prompt
(`-w` must be last):

```sh
security add-generic-password -U -a GEMINI_API_KEY -s container-hardening-work-bench.gemini -w
```

Never put keys in command arguments, source, artifacts or chat. The static-probe
compiler and Slim subprocesses do not receive the provider key variables.
An earlier live Argon request returned HTTP 429 on 2026-10-24. Account access and
quota can change; each new run reports its actual mode and completion status.
Successful tools-mode validation is not evidence of a successful live AI run.
An API failure returns an error, never a silent model-to-tools fallback.

## Earlier Containerfile-generation command

```sh
./bin/breachbench harden gemini --file Containerfile --output Containerfile.gemini

./bin/breachbench harden gemini \
  --file Containerfile --output Containerfile.gemini \
  --target app:gemini --baseline app:before \
  --app-command-json '["node","/app/test.js"]'
```

Only the selected Containerfile is sent to Gemini; review it for embedded secrets.
The candidate is written to a new file, never over an existing destination. The
response reports proposed changes and limitations, not passed tests. `--target`
opts into building a new image. `--baseline` additionally opts into the legacy
containment tests below and requires both `--target` and a valid finite application
command before an API request. Omitting `--baseline` builds without testing.
Build `RUN` instructions use no network, but `FROM`, remote `ADD`, or a custom
Dockerfile frontend may still fetch content. Review generated build instructions
as code. Build/test failures preserve the candidate file and return nonzero.

## Legacy Node containment tests and demos

These retain their earlier scope and need no key:

```sh
# Imported demo, not BreachBench's native harden demo OUTPUT command.
./bin/breachbench harden image demo
./bin/breachbench harden image demo --baseline node:24-trixie-slim

./bin/breachbench harden pentest --baseline app:before --image app:after \
  --probe-bin node --app-command-json '["node","/app/test.js"]'
```

The imported `demo` needs an already-local Node-compatible base, builds a
synthetic request/response fixture and removes its own images/containers. It does
not run the user's application. `pentest` requires Node in both images for its
UID/filesystem probes; `--probe-bin` may select its executable path. The supplied
application argv replaces the image entrypoint, must make a meaningful finite
check, and must exit rather than run a server.

Both sides use no networking or host mounts, dropped capabilities,
no-new-privileges and resource limits. Unlike generic `auto`, this older positive
control deliberately forces the baseline root/writable. The candidate is
non-root/read-only. Its exact marker probes check `/bin/sh`, `/bin/bash`,
`/bin/ash`, `/usr/bin/sh`, `/busybox sh` and `/bin/busybox sh`. Success requires a
working application, root/writable/accessibly shelled baseline, and denied writes
plus unavailable tested shells in the candidate. Missing probe runtimes, daemon
failures, timeouts or failed checks are inconclusive/nonzero, with partial JSON
evidence. No remote exploit, universal shell absence or runtime-RCE prevention is
established. Network/syscall/LSM enforcement is not tested.

The separate fixed public Node `tool-demo` retains the old model/Slim path:

```sh
./bin/breachbench harden tool-demo --slim /absolute/path/to/slim \
  --artifacts ./legacy-demo-results

./bin/breachbench harden tool-demo --scripted --demo-engine=docker \
  --artifacts ./scripted-demo-results
```

It requires an already-local `node:24-trixie-slim`. The latter reports
`scripted-docker-demo`, `model: none`, not automatic dependency discovery.
`--scripted` without the Docker engine exercises Slim without a model. Legacy
`--slim`, `--offline-workload` and `--trusted-workload` are not generic
`auto`/`agent` options. The demo retains its baseline/candidate tags and private
Slim artifacts where applicable. Native profiling can use privileged sensors;
use an isolated host and keep the executable and matching sensor together.
The last native Slim/Mint profiling run failed with sensor code 2 on ARM64 Docker
Desktop 27.5.1 (release asset reporting x.1.42.2 and Mint 1.41.8), not successful
profiling. Neither this nor Argon quota blocks generic `tools` mode.

## Optional standalone tools and deployment checks

These wrappers remain independent of generic hardening; no scan/triage/Slim step
is required for `auto`:

```sh
./bin/breachbench harden image inspect --container existing-container
./bin/breachbench harden image config --path . > config.json
./bin/breachbench harden image scan --image app:before > before.json
./bin/breachbench harden image build --path . --file Containerfile --target app:candidate
./bin/breachbench harden image minify --image app:candidate --target app:slim
./bin/breachbench harden image run --image app:candidate --user 65532:65532 -- php /app/tests/smoke.php
./bin/breachbench harden image verify --container existing-container
./bin/breachbench harden image scan --image app:candidate > after.json
./bin/breachbench harden image compare --before before.json --after after.json
```

`run` uses read-only root, non-root UID:GID, dropped capabilities,
no-new-privileges, no network, resource limits and bounded noexec `/tmp`. Commands
after `--` are argv, not shell text. It forwards no user credentials, environment
values or host mounts, though image environment defaults remain. Failed commands
return nonzero; interrupted/failed-host cleanup can need manual attention.
`inspect` redacts environment/mount-source values. Configuration `verify` reports
`baseline_passed: false` for failed controls; its exit status covers execution or
parsing errors, so consumers must inspect that field.

`run --seccomp /absolute/profile.json` accepts a reviewed restrictive profile;
`--apparmor profile-name` references an already-loaded profile. Otherwise Docker's
defaults apply. These options do not generate, load or prove LSM enforcement.
Generated Slim profiles need separate review and workload testing. Trivy scan
comparisons cover vulnerability findings, not secrets or policy findings. Keep
original scan/SBOM evidence: missing metadata is not fewer vulnerabilities, and
this workflow does not claim packages are unreachable.

For Kubernetes, review explicit non-root UID/GID, no privilege escalation,
read-only root, dropped capabilities, resource limits and RuntimeDefault seccomp;
disable unnecessary service-account tokens. Default-deny network policy needs an
enforcing CNI and explicit required destinations. This workflow neither modifies
a live cluster nor infers those destinations. Independently test denied egress,
syscalls and privilege changes in the actual deployment. Read-only root does not
protect writable mounts; allowed connections and HTTP responses remain possible
exfiltration paths. Scope credentials separately and record untested behaviours.
