#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
toolroot="${XDG_DATA_HOME:-$HOME/.local/share}/breachbench/tools"
export PATH="$toolroot/go/bin:$toolroot/node/bin:$toolroot/trivy:$toolroot/slim:$toolroot/strace/usr/bin:$toolroot/cluster:$PATH"
# Keep build and scanner caches off the Windows-mounted source tree.
export GOCACHE="/tmp/breachbench-go-cache-$(id -u)"
export GOPATH="/tmp/breachbench-go-path-$(id -u)"
export TRIVY_CACHE_DIR="/tmp/breachbench-trivy-cache-$(id -u)"
export BREACHBENCH_WORKBENCH_ROOT="/tmp/breachbench-workbench-$(id -u)"
if [[ "${1:-}" == "cluster-test" ]]; then
  exec node hardening/cluster.mjs
fi
if [[ "${1:-}" == "remediation-test" ]]; then
  node hardening/demo/complete-config.mjs
  exec node hardening/cli.mjs run .breachbench/remediation-config.json .breachbench/remediation
fi
if [[ "${1:-}" == "resource-test" ]]; then
  exec node hardening/runtime-check.mjs
fi
if [[ "${1:-}" == "lsm-test" ]]; then
  exec node hardening/lsm.mjs verify
fi
if [[ "${1:-}" == "versions" ]]; then
  go version
  node --version
  trivy --version
  slim --version
  strace -V | head -n 1
  exit 0
fi
if [[ "${1:-}" == "slim-demo" ]]; then
  node hardening/demo/slim-config.mjs
  exec node hardening/cli.mjs run .breachbench/slim-config.json .breachbench/live-slim-demo
fi
if [[ "${1:-}" == "lsm-check" ]]; then
  exec node hardening/profiles.mjs lsm-check "${2:-.breachbench/seccomp-demo/lsm-support.json}"
fi
if [[ "${1:-}" == "trace-demo" ]]; then
  exec node hardening/profiles.mjs trace "${2:-hardening/demo/config.json}" "${3:-.breachbench/seccomp-demo}"
fi
if [[ "${1:-}" == "validate-seccomp" ]]; then
  exec node hardening/profiles.mjs validate "${2:-.breachbench/seccomp-demo/seccomp.candidate.json}" "${3:-.breachbench/seccomp-demo/seccomp.reviewed.json}"
fi
if [[ "${1:-}" == "seccomp-demo" ]]; then
  outdir="${2:-.breachbench/seccomp-demo}"
  node hardening/profiles.mjs trace hardening/demo/config.json "$outdir"
  node hardening/profiles.mjs validate "$outdir/seccomp.candidate.json" "$outdir/seccomp.reviewed.json"
  exec node hardening/cli.mjs run "$outdir/config.json" "$outdir/workflow"
fi
exec node hardening/cli.mjs "$@"
