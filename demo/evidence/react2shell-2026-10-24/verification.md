# Final supplied-image verification

Verified locally on 2026-10-24 using the rebuilt repository CLI, deterministic tools mode.

- Source: `local/react2shell-baseline:demo`, image ID `sha256:d2415548ff2f948a06337cd1d707b707c660754dbf48e221b0057304eba291cb`.
- Result: `local/react2shell-hardened:verified`, image ID `sha256:a1c4843597993116b6621da4c418e266f6c1c5cb853ae5d99462292c9383cf03`.
- Generic workflow completed on the first candidate. Eleven existing shell/package-tool executable entries were removed. Retained application and runtime payload bytes were copied unchanged.
- Original ENTRYPOINT/CMD served the homepage and `/api/health` successfully before and after; see `report.json`.
- A separate disposable verification container also successfully submitted the ordinary greeting Server Action form. Homepage, health, and form POST returned HTTP 200 and the expected markers/greeting.
- Verification used UID:GID `65532:65532`, read-only root, network `none`, all capabilities dropped, no-new-privileges, 512 MiB RAM, one CPU, 128 PIDs, and 64 MiB `noexec,nosuid,nodev` tmpfs mounts only at `/tmp` and `/app/.next/cache`. No host ports, secrets, or host application mounts were supplied. The verification container was removed.
- Generated `compose.json` passed `docker compose config --quiet`.

Unchanged versions: Debian 13.7, Node.js 24.22.1, Next.js 15.1.0, top-level React/React DOM 19.0.0. Next.js compiled React remained `19.0.0-rc-7283a213-20241206`; the bundled RSC package has no standalone version field. One built Server Action remained present.

The following SHA-256 values matched the baseline exactly:

| File relative to `/app` | SHA-256 |
|---|---|
| `node_modules/next/dist/compiled/react-server-dom-webpack/cjs/react-server-dom-webpack-server.node.production.js` | `bb5696406b2a69d6cddd73225f14cc848fc56cd877560c21d6292e9f157d0a90` |
| `node_modules/next/dist/compiled/next-server/app-page.runtime.prod.js` | `3fb165e879bfb6ffc024a7b34f2111a63a3aaa9da8df486cf7d3f4fe1c299f7d` |
| `package-lock.json` | `1f36c48ff8d4552c61322e02f0797cad2cb165aa254cab75ce1d2750ebca431d` |

The App Router setup remains in the affected range of the [official Next.js React2Shell advisory](https://nextjs.org/blog/CVE-2025-66478). No exploit was attempted. These checks establish selected functionality and containment, not complete application coverage, removal of React2Shell, or prevention of arbitrary JavaScript execution. Required runtime configuration must accompany the image. Live Argon remains unverified because the earlier API attempt hit quota; no model success or fallback was claimed.
