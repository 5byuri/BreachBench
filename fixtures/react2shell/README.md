# Intentionally vulnerable React2Shell containment fixture

**Local isolated testing only. Never publish this image, expose its port publicly, supply real credentials, or use it in production.**

This is an ordinary, production-built Next.js App Router application, not a simulated shell endpoint. It renders a fictional **The British Bank** dashboard, exposes a health endpoint, and includes a harmless transfer-preview Server Action. There is no exploit payload, command execution handler, or backdoor in the application.

The bank uses fictional GBP balances, transactions and allowlisted demo payees. A transfer changes the balance and activity shown for the current URL only; **Reset demo** returns to the starting data. Nothing is persisted, no money moves, and there is no real login, payment provider or banking integration. Never enter real customer data or credentials. This is a container-hardening fixture, not production banking software.

The image deliberately pins Next.js `15.1.0`, React `19.0.0`, and React DOM `19.0.0`. The official Next.js advisory identifies App Router applications on the 15.1 release line before `15.1.9` as affected by the original React2Shell issue. React's upstream advisory tracks it as CVE-2025-55182; CVE-2025-66478 tracks the downstream Next.js impact. Do not infer affectedness from the top-level React version alone: Next.js bundles its own RSC implementation.

Primary sources, verified 2026-10-24:

- [React security advisory](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)
- [Next.js security advisory](https://nextjs.org/blog/CVE-2025-66478)

The `node:24-trixie-slim` base is Debian 13 (trixie), with Node.js already installed. The app runs using Node directly, not an `npm start` shell wrapper. Hardening must preserve the installed application and runtime versions; a separate real production remediation would require upgrading the affected dependencies.

Build from this directory:

```sh
docker build -f Containerfile -t local/react2shell-baseline:demo .
```

For a manual smoke test, keep networking disabled, publish no host ports, and use no real secrets or host mounts:

```sh
docker run --detach --rm --name react2shell-local-demo --network none \
  --cap-drop ALL --security-opt no-new-privileges:true \
  local/react2shell-baseline:demo
docker exec react2shell-local-demo node -e \
  'fetch("http://127.0.0.1:3000/api/health").then(async r => { if (r.status !== 200) throw Error("health failed"); console.log(await r.text()); }).catch(e => { console.error(e.message); process.exitCode = 1; })'
docker rm -f react2shell-local-demo
```

The Next.js server still listens inside the container; only its own loopback address is used for this smoke test. Wait briefly for startup before the request. This Node command is a fixture-specific manual check, not a dependency of the generic hardening workflow.

`workload.json` declares deterministic HTTP smoke checks for the generic hardening workflow. They verify that the actual image entrypoint starts and the selected application paths still work. They do not prove complete functionality or absence of vulnerabilities. The ordinary transfer-preview form can also be exercised manually; no malicious request is necessary for these containment checks. The pure banking model is tested with `node --test app/bank.test.mjs` from this directory.

The comparison intentionally leaves the vulnerable Next.js implementation present. Losing tested shell/tool access and write privileges after hardening does **not** establish that React2Shell exploitation or arbitrary JavaScript execution is prevented. Patching is still required for production.

## Verified fixture build

Built and tested locally on 2026-10-24:

| Component | Observed version |
| --- | --- |
| Debian | 13.7 |
| Node.js | 24.22.1 |
| Next.js | 15.1.0 |
| Top-level React / React DOM | 19.0.0 / 19.0.0 |
| Next.js compiled React and bundled RSC peer requirements | 19.0.0-rc-7283a213-20241206 |

Next.js's bundled `react-server-dom-webpack-builtin/package.json` has no `version` field. Its peer requirements and compiled React identify the bundled prerelease above; affectedness is established from the official Next.js advisory and the actual App Router configuration, not by inventing a package version.

The bundled production RSC file `node_modules/next/dist/compiled/react-server-dom-webpack/cjs/react-server-dom-webpack-server.node.production.js` had SHA-256 `bb5696406b2a69d6cddd73225f14cc848fc56cd877560c21d6292e9f157d0a90`. This is useful for checking byte preservation, not an exploit test or a claim that this is the only relevant runtime file.

The original fixture image entrypoint started successfully. The dynamic homepage and health endpoint returned HTTP 200, and its original greeting Server Action produced the expected greeting. Those historical checks predate the fictional bank UI and are not a fresh bank-demo verification. The pure model tests and current browser/run evidence must be checked separately for the bank build. No malicious React2Shell request was sent.

The [post-hardening verification record](verification-evidence.md) shows the same application working as non-root with a read-only root filesystem, narrowly writable tmpfs paths, and no network outside container loopback. It also records unchanged dependency versions and matching production RSC/App Router hashes.
