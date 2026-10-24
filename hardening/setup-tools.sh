#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
downloads="$PWD/.breachbench/tools/downloads"
toolroot="${XDG_DATA_HOME:-$HOME/.local/share}/breachbench/tools"
mkdir -p "$toolroot/node" "$toolroot/trivy" "$toolroot/slim" "$toolroot/strace/lib"
printf 'Installing toolchain into %s\n' "$toolroot"
tar -xzf "$downloads/go1.27.3.linux-amd64.tar.gz" -C "$toolroot"
tar -xf "$downloads/node-v24.11.1-linux-x64.tar.xz" --strip-components=1 -C "$toolroot/node"
tar -xzf "$downloads/trivy_0.76.1_Linux-64bit.tar.gz" -C "$toolroot/trivy"
tar -xzf "$downloads/dist_linux.tar.gz" --strip-components=1 -C "$toolroot/slim"
if [[ ! -x "$toolroot/strace/usr/bin/strace" ]]; then
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT
  (cd "$tmpdir" && apt-get download strace >/dev/null && dpkg-deb -x strace_*.deb "$toolroot/strace")
fi
cp -f /lib/x86_64-linux-gnu/libunwind*.so* "$toolroot/strace/lib/" 2>/dev/null || true
export PATH="$toolroot/go/bin:$toolroot/node/bin:$toolroot/trivy:$toolroot/slim:$toolroot/strace/usr/bin:$PATH"
go version
node --version
trivy --version
slim --version
strace -V | head -n 1
