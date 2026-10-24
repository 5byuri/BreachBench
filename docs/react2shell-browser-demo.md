# The British Bank: real React2Shell browser demo

This is a fictional British banking sandbox on an ordinary Next.js App Router
website with React Server Components and a harmless transfer-preview Server
Action. It uses GBP balances and dummy payees only. No money moves, no data is
persisted, and there is no real login or banking integration. A transfer changes
the current URL's preview; **Reset demo** returns to the original data.
Next.js remains pinned to 15.1.0 and React / React DOM to 19.0.0. There is no
artificial command-execution endpoint. The
application intentionally remains vulnerable: use only this local disposable
lab, never real credentials, host application mounts or a production deployment.

The page displays its actual server UID. A root baseline displays `0`; a candidate
started with the verified runtime policy displays `65532`. This is runtime
identity evidence, not a vulnerability scan or an exploit demonstration.

## Build

From the BreachBench repository root:

```sh
go build -o bin/breachbench .
go build -o bin/react-demo-web ./cmd/react-demo-web
node --test fixtures/react2shell/app/bank.test.mjs
docker build -f fixtures/react2shell/Containerfile \
  -t local/react2shell:british-bank-demo fixtures/react2shell
```

## Start the baseline

```sh
docker run --detach --rm --name breachbench-bank-before \
  --network none --memory 512m --cpus 1 --pids-limit 128 \
  local/react2shell:british-bank-demo
./bin/react-demo-web --container breachbench-bank-before --port 3000
```

Open `http://127.0.0.1:3000`. The forwarder runs in the foreground; use a second
terminal for the hardening command below. Its host listener is fixed to IPv4
loopback, with no option to bind publicly. No Docker ports are published. The
container stays on `network=none`.

The demo-only forwarder invokes a fixed Node TCP relay through `docker exec`.
It forwards the browser's real HTTP traffic to the website's container loopback,
including assets and normal form POSTs. It is not part of generic image profiling
and deliberately depends on this Node fixture. It uses no shell, app credentials
or host mounts. Connections are bounded and time-limited; stopping the container
or interrupting the forwarder ends browser access. Application responses can still
return data: this is not proof that code execution or exfiltration is impossible.

## Harden, with readable output

```sh
demo_parent=$(mktemp -d /tmp/breachbench-bank.XXXXXX)
./bin/breachbench harden agent --format human \
  --image local/react2shell:british-bank-demo \
  --target "local/react2shell:bank-hardened-$(basename "$demo_parent")" \
  --model gemini-4-argon \
  --checks fixtures/react2shell/workload.json \
  --policy fixtures/react2shell/policy.json \
  --artifacts "$demo_parent/results"
```

`agent` uses the existing Gemini environment/Keychain configuration. Use `auto`
instead of `agent` for an explicitly deterministic tools run. API failures do not
silently switch modes. `--format auto` (the default) is human-readable on a
terminal and JSON when piped; `--format json` forces machine-readable stdout.
The complete `report.json`, `comparison.md` and deployment `compose.json` remain
in the artifact directory. Console formatting does not change validation.

## View the hardened website

In the same shell that has `demo_parent` set, start the generated deployment:

```sh
docker compose -p breachbench-bank-after \
  -f "$demo_parent/results/compose.json" up -d
./bin/react-demo-web \
  --container "$(docker compose -p breachbench-bank-after -f "$demo_parent/results/compose.json" ps -q app)" \
  --port 3001
```

Open `http://127.0.0.1:3001`. Both websites should serve the bank dashboard and
transfer-preview form. Try a fictional £25 transfer, check that the displayed
current-account balance falls by £25, then use **Reset demo**. Compare the live
UID under **Container hardening lab** and the terminal's containment results.
Use a new Compose project name if that name is already in use. Both forwarders
and both app containers have no published Docker ports. This demo intentionally
uses `network=none`; the forwarders do not establish general network-policy or
egress enforcement.

## Cleanup

Interrupt each forwarder with Ctrl+C, then remove only these demo containers:

```sh
docker stop breachbench-bank-before
docker compose -p breachbench-bank-after \
  -f "$demo_parent/results/compose.json" down
```

The baseline uses `--rm`; the hardened Compose deployment is removed by `down`.
Images and evidence are retained. Do not delete or replace unrelated containers.
Hardening does not patch React2Shell; no React2Shell exploit is used by these
checks. The preserved vulnerable versions are for this isolated demonstration
only.
