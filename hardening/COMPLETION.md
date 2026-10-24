# Hardening implementation and verification

The seven CLI tools are implemented and integrated with the Go entry point through `go run . harden`. Gemini in Antigravity can inspect the repository, choose workload configuration and finding-specific remediation recipes, execute the tools and review the resulting evidence. Direct Gemini API access remains optional; the supplied account currently reports an exhausted monthly spending cap.

## Verified controls

| Requirement | Implementation and evidence |
| --- | --- |
| Work-bench | Real pinned in-repository CLI; extracted filesystem cache bound to exact source ID and work-bench commit; inspection uses the immutable ID |
| Trivy | Vulnerability, secret, image configuration and source/deployment configuration scans; normalized JSON component/fix findings; raw secret matches excluded |
| Slim | Representative foreground/background/uncommon-path workload tracing; explicit retains for recovery paths and scanner metadata; functional/enforcement tests before review eligibility |
| Runtime | Non-root, drop ALL capabilities, no-new-privileges, read-only root with scoped writable tmpfs, no privileged mode/host mounts/Docker socket; memory/CPU/PID limits |
| Runtime enforcement | Live CPU throttling counters, PID-limit EAGAIN and OOMKilled/exit-137 tests in disposable cgroup-v2 containers |
| Seccomp | Native-architecture default-deny profile; five-phase traces; explicit agent permission review bound to source image, exact profile hash and trace hashes; positive calls and harmless negative EPERM probes |
| AppArmor | Generated candidate and permission inventory; repository-reviewed fixture template; actual enforced-label, positive-functionality and denied-write checks passed on a compatible hosted Linux runner |
| SELinux | Dedicated-container Udica CIL candidate generator, environment scrubbing, review inventory and deployment label support. Enforcement remains unverified without a SELinux-enabled host |
| Network | Isolated kind v0.30.0/Kubernetes v1.34.0 with Calico v3.31.0. Namespace default-deny, explicit DNS UDP/TCP, API and database allowances, ingress allowances, denied peer and denied Kubernetes API egress |
| Credentials | Runtime-only random database canary in a readonly Secret volume scoped to app/database; incorrect credential rejected; no mount in unrelated peer; no service-account token; service account cannot list Secrets; canary absent from all saved image objects/layers |
| Review and rollback | Separate candidate tags, source ID recorded, no automatic promotion, stale evidence invalidated, image/deployment results separated |

Network negative tests first establish the same peer is reachable before policy and remains reachable from a control pod afterward. A timeout alone is not accepted as proof that an unavailable peer was blocked. The tests use controlled HTTP/database peers; they do not pretend to validate production API or SQL behavior.

## Run the implementation

From the repository root on Windows, with Ubuntu WSL Docker integration enabled:

```powershell
node --test hardening/test/*.test.mjs
wsl -d Ubuntu -- bash hardening/setup-cluster.sh
wsl -d Ubuntu -- bash hardening/wsl-run.sh cluster-test
wsl -d Ubuntu -- bash hardening/wsl-run.sh resource-test
wsl -d Ubuntu -- bash hardening/wsl-run.sh remediation-test
wsl -d Ubuntu -- bash hardening/wsl-run.sh slim-demo
wsl -d Ubuntu -- bash hardening/wsl-run.sh go-test
```

Native Linux uses the same shell wrapper without the `wsl -d Ubuntu --` prefix. The Go CLI also exposes `harden run`, `harden verify`, each of the seven tools, and `harden cluster-test`, `resource-test`, `lsm-test`, `remediation-test`, `slim-demo`. Unknown modes are rejected; no shell command string is interpolated.

`cluster-test` owns a new randomly named `breachbench-*` kind cluster, uses an explicit private kubeconfig/context for every kubectl call, and removes its cluster and kubeconfig on completion. Existing clusters are never selected. The kind control-plane container needs privileges to run Kubernetes; workload pods remain restricted, non-root and without host mounts. The network and credential checks use no cloud accounts or real user credentials.

## Finding-specific image improvements

`remediation-test` enables constrained recipes through configuration. Each recipe records the finding IDs and rationale in `remediation-plan.json` and the final report. The reference workload uses only the Python standard library and explicitly declares that it never installs packages at runtime, so the approved recipe removes its unused vulnerable pip installer. An application HTTP healthcheck is added independently. Other workloads must declare their own requirements; removal is rejected without the explicit declaration.

An attempted pip upgrade was rejected because rescanning discovered new HIGH/CRITICAL bundled dependencies. Its local evidence is preserved in `.breachbench/remediation-first-rejected`. The revised removal candidate passed functionality and enforcement with no new HIGH/CRITICAL finding. This demonstrates that an apparently actionable upgrade is not automatically accepted. Package/runtime changes are not inferred to fix all CVEs, and historical base layers are retained for rollback.

## Profile review and host verification

Use `trace-demo CONFIG OUTPUT` to capture new workloads. Capture and automated structural validation never grant permission review. An explicit reviewer supplies `--review-type agent-permission-review` or a truthful human review type, plus structured evidence containing `reviewer`, `method` and the traced `sourceImageId`. The review binds the canonical profile SHA256 and all five trace SHA256 values; changed images, profile permissions or trace contents require renewed review. `seccomp-demo` will not approve a newly observed candidate automatically.

The current explicitly reviewed reference profile and its workflow evidence live in `.breachbench/completion-seccomp-final`. LSM candidates generated from those traces live in `.breachbench/completion-lsm`. These raw local traces can contain application data and must not be committed indiscriminately.

AppArmor verification runs with `node hardening/lsm.mjs verify` on a capable Linux host. A custom profile is loaded only under the dedicated fixture name, a control write succeeds without it, the enforced label and denied write are checked with it, and the profile is unloaded afterward. Unsupported hosts return `unverified-host` and a nonzero exit; they never fall back silently. WSL is still unverified for AppArmor/SELinux. AppArmor enforcement passed in [Linux CI run 40113106357](https://github.com/5byuri/BreachBench/actions/runs/40113106357), whose uploaded `hardening-control-reports` artifact includes the positive/negative results and cleanup evidence.

For SELinux, `node hardening/lsm.mjs selinux-generate breachbench-CONTAINER OUTPUT` runs Udica against a dedicated controlled container after stripping environment values from its inspection. Review emitted CIL and workload AVCs, then load the reviewed module and templates on a SELinux-enabled host. Configure the reviewed domain through `selinuxType` and provide an `lsm` enforcement test. Do not load generic unreviewed `audit2allow` output or claim AppArmor tests prove SELinux enforcement.

## Remaining risks and deployment boundaries

- Existing base/runtime vulnerabilities remain. Containment neither patches vulnerable PHP nor prevents every exploit.
- Observation cannot capture every future workload. The syscall-name allowlist has no argument filtering; ioctl, clone3 and memory-management operations remain broad.
- AppArmor's `abstractions/base` varies by host. The repository review concerns a fixture template, not arbitrary applications or every abstraction version.
- SELinux enforcement is not verified here. IPv6 requires a dual-stack target test; local CNI conformance is IPv4.
- Named production databases, APIs, persistent volumes and credential issuers require application-specific configuration and tests. No user production deployment has been changed.
- Network/credential conformance reports concern their own generated manifests and CNI. They do not retroactively mark every workload's deployment policy as enforced.
- Secret-canary layer checking supports uncompressed/gzip objects and fails on unsupported zstd objects instead of claiming coverage. Trivy supplies general secret-pattern detection separately.
- Slim retains dpkg/OS metadata for scanner visibility, which can still describe files removed from the runtime filesystem. Review actual affected files before asserting vulnerability removal.

The English source, configuration, documentation and CI workflow are versioned on `feat/gemini-container-hardening`. Fetch/pull main before each reviewed push; the teammate's separate `feat/harden-pr-bot` branch is not merged without reviewing its independent changes.
