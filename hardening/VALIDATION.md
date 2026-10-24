# Local validation snapshot

This historical snapshot is superseded by [the completion and host/cluster verification report](COMPLETION.md). Current unit-test counts and newer profile evidence should be read from the latest run, not the older numbers below.

Validated on Windows with Ubuntu WSL2 and Docker Desktop's Linux engine. This records the demo workload, not a production deployment or Gemini API run.

Installed user-local Linux tools: Go 1.27.3, Node 24.11.1, Trivy 0.76.1, and `strace` 6.8 (`~/.local/share/breachbench/tools/strace`). The official SlimToolkit 1.40.11 release asset downloaded here identifies itself as `mint ... x.1.42.2` when queried; its provenance and actual SHA256 are recorded in `.breachbench/tools/downloads/manifest.json`. No system-wide Go, Node or scanner installation was replaced.

| Check | Standard candidate | Slim candidate | Reviewed default-deny seccomp candidate |
| --- | --- | --- | --- |
| In-repo work-bench inspection | Passed | Passed | Passed |
| Trivy image and configuration scanning | Passed | Passed | Passed |
| Foreground, background, uncommon-path tests | Passed on source and candidate | Passed on source and candidate | Passed on source and candidate |
| Non-root, read-only filesystem, writable tmpfs | Passed | Passed | Passed |
| Capabilities and privilege-escalation controls | Passed | Passed | Passed |
| Explicit harmless syscall denied | Passed (`getppid` EPERM) | Passed (`getppid` EPERM) | Passed (`SCMP_ACT_ERRNO`, 60 allowed; `getpid` allowed, `getppid` + `getpgid` denied with EPERM under `Seccomp: 2`) |
| Outbound routing denied | Passed | Passed | Passed |
| Configured CPU, memory, PID limits | Passed | Passed | Passed |
| Debian scanner visibility | Preserved | Preserved | Preserved |
| Docker-reported image size | 43,266,089 bytes | 20,017,838 bytes | 43,266,089 bytes |
| Acceptance | Eligible for review | Eligible for review | Eligible for review |

The original image measured 43,265,958 bytes. Slim reduced this by 23,248,120 bytes (53.73%). Image IDs and full evidence are in `.breachbench/live-demo/report.json`, `.breachbench/live-slim-demo/report.json`, and `.breachbench/seccomp-demo/workflow/report.json` (with per-phase syscall traces in `.breachbench/seccomp-demo/traces/`, observation report in `.breachbench/seccomp-demo/syscall-observation.json`, unreviewed candidate in `.breachbench/seccomp-demo/seccomp.candidate.json`, reviewed profile in `.breachbench/seccomp-demo/seccomp.reviewed.json`, previous 59-syscall snapshot in `.breachbench/seccomp-demo/seccomp.reviewed.v1-59syscalls.json`, and LSM host check in `.breachbench/seccomp-demo/lsm-support.json`). All retain the original image ID for rollback; no candidate was promoted or deployed, and `hardening/demo/seccomp.json` / `hardening/demo/config.json` remain untouched.

**Remaining findings:** both final reports retain 172 Trivy findings, including 44 HIGH and zero CRITICAL findings in this scan. No claim is made that these vulnerabilities were fixed. Retained dpkg metadata may also describe removed files; review affected components against the actual filesystem. Acceptance here means the configured functionality/control gates passed with no new HIGH/CRITICAL finding or lost OS scanner coverage. It is not a vulnerability-free certification.

The first Slim attempt was rejected for a missing `libffi` probe dependency and an unnecessary inherited `GPG_KEY` build variable. The workload now exercises the probe dependency, removes unused build variables, and retains Debian release/package metadata so reduced scan visibility cannot masquerade as remediation.

Local regression suite: 18 passing tests, including stale evidence, input changes, tool scope/order, missing workload/enforcement tests, vulnerability regressions, Slim API configuration, lost OS scanner visibility, separation between automated candidate validation (`reviewed: false`, `reviewType: "automated-validation-only"`) and explicit permission review (`reviewType` + `reviewEvidence`), work-bench extracted filesystem cache binding to exact image ID with invalidation on image change, and AppArmor/SELinux unverified host status checks.

Still unverified: Gemini API access/tool calls until the account owner supplies a key and model; AppArmor and SELinux profile generation and enforcement on a compatible Linux host (`lsm-support.json` records `overallStatus: "partial-seccomp-only-apparmor-selinux-unverified"`, `/sys/module/apparmor/parameters/enabled = N`, `/sys/fs/selinux/enforce` absent, and Docker `SecurityOptions = ["name=seccomp,profile=builtin","name=cgroupns"]`, keeping both `status: "unverified-on-host"`, `verified: false`, `tested: false`, `enforced: false`); Kubernetes allow/deny policies on a CNI-enabled cluster; and resource-limit saturation behavior. Container hardening does not repair vulnerable runtimes or completely prevent exploitation.

Reproduce with the commands in [the setup guide](README.md). Full reports and extracted filesystem data stay local in ignored directories; summaries in this file contain no credentials.
