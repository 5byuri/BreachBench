# Real Next.js fixture: post-hardening verification

Verified locally on 2026-10-24. This records observed results, not an exploit test.

Baseline: `local/react2shell-baseline:demo`

Hardened: `local/react2shell-hardened:generic-1`

Hardened image ID: `sha256:26fa6b41998f260718ddda250fd4b7336f0f0e3864df2d6991f972d10659ebaf`

## Dependencies and runtime were not upgraded

| Component | Baseline | Hardened |
| --- | --- | --- |
| Debian | 13.7 | 13.7 |
| Node.js | 24.22.1 | 24.22.1 |
| Next.js | 15.1.0 | 15.1.0 |
| React | 19.0.0 | 19.0.0 |
| React DOM | 19.0.0 | 19.0.0 |
| Next.js compiled React | 19.0.0-rc-7283a213-20241206 | 19.0.0-rc-7283a213-20241206 |
| Built Node Server Actions | 1 | 1 |

The following files had identical SHA-256 hashes in both images:

| File, relative to `/app` | SHA-256 in both images |
| --- | --- |
| `node_modules/next/dist/compiled/react-server-dom-webpack/cjs/react-server-dom-webpack-server.node.production.js` | `bb5696406b2a69d6cddd73225f14cc848fc56cd877560c21d6292e9f157d0a90` |
| `node_modules/next/dist/compiled/next-server/app-page.runtime.prod.js` | `3fb165e879bfb6ffc024a7b34f2111a63a3aaa9da8df486cf7d3f4fe1c299f7d` |
| `package-lock.json` | `1f36c48ff8d4552c61322e02f0797cad2cb165aa254cab75ce1d2750ebca431d` |

These checks read package metadata and original image files without modifying them. Next.js's bundled RSC package has no standalone `version` field; no version was invented for it. The fixture's actual App Router setup and Next.js `15.1.0` place it in the affected range documented in the [official Next.js advisory](https://nextjs.org/blog/CVE-2025-66478). The known-affected implementation remains present: container hardening did not patch React2Shell.

## The normal Server Action still works under the hardened policy

A new disposable container started the hardened image's original entrypoint and command. Its inspected runtime configuration was:

- UID:GID `65532:65532`.
- Read-only root filesystem.
- Only `/tmp` and `/app/.next/cache` made writable with 64 MiB tmpfs mounts using `rw,noexec,nosuid,nodev,mode=1777`.
- `network=none`; no published ports, secrets, or host mounts.
- All capabilities dropped; `no-new-privileges` enabled.
- Memory 512 MiB, one CPU, PID limit 128.

From inside that isolated container, a fixed Node check used only `http://127.0.0.1:3000`. It fetched the actual generated HTML form and submitted its ordinary hidden Server Action field plus a plain name. It did not construct a malicious RSC payload.

| Application check | Hardened result |
| --- | --- |
| Dynamic App Router homepage | HTTP 200; expected page marker present |
| `/api/health` | HTTP 200; `status` was `healthy` |
| Ordinary greeting Server Action form POST | HTTP 200 after its normal redirect; expected greeting present |
| Check process effective UID:GID | `65532:65532` |

The corresponding ordinary homepage, health, and greeting form checks had also passed on the baseline. The new verification container was removed afterward; the baseline and hardened images were retained for the demo.

## What this does not establish

No React2Shell exploit, remote shell, external target, or arbitrary command endpoint was used. These results establish selected application compatibility and byte preservation under the stated runtime controls, not complete application coverage, absence of vulnerabilities, or prevention of arbitrary JavaScript execution. Writable tmpfs paths and the application runtime remain available. A real production deployment still requires patching the affected dependencies.
