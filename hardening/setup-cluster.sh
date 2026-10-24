#!/usr/bin/env bash
set -euo pipefail
toolroot="${XDG_DATA_HOME:-$HOME/.local/share}/breachbench/tools"
mkdir -p "$toolroot/cluster"
cd "$toolroot/cluster"
for item in kind kubectl; do
  if [[ "$item" == kind ]]; then
    url='https://github.com/kubernetes-sigs/kind/releases/download/v0.30.0/kind-linux-amd64'
    sumurl="$url.sha256sum"
  else
    url='https://dl.k8s.io/release/v1.34.0/bin/linux/amd64/kubectl'
    sumurl="$url.sha256"
  fi
  curl --fail --location --retry 2 "$url" -o "$item.download"
  expected="$(curl --fail --location --retry 2 "$sumurl" | awk '{print $1}')"
  printf '%s  %s\n' "$expected" "$item.download" | sha256sum --check
  install -m 0755 "$item.download" "$item"
done
curl --fail --location --retry 2 'https://raw.githubusercontent.com/projectcalico/calico/v3.31.0/manifests/calico.yaml' -o calico-v3.31.0.yaml
sha256sum kind kubectl calico-v3.31.0.yaml > manifest.sha256
./kind version
./kubectl version --client
