# Image-hardening migration, 2026-10-24

The supplied-image work previously developed in
`l3montree/container-hardening-work-bench` is now part of BreachBench's own Go
module. No runtime reference to that old checkout or its binary is needed.

| Previous progress | BreachBench location |
|---|---|
| Hardening, Gemini/Argon, Slim adapter and containment engine/tests | `internal/imagehardening/` |
| Cross-compiled static probe and its tests | `internal/imagehardening/internal/containmentprobe/` |
| Real vulnerable Debian/Next.js application and workload policy | `fixtures/react2shell/` |
| Older fixed tool fixture | `fixtures/tool-hardening/` (also embedded by the engine) |
| Commands formerly called through the old executable | `breachbench harden auto/agent/...` or `breachbench harden image ACTION` |
| Old command-line compatibility executable | `cmd/container-hardening-agent/` |
| Reports and historical blocker evidence | `demo/evidence/` |
| Usage, limits and credentials setup | `docs/image-hardening.md` |

The existing application-bundle hardener, tracing/scraping commands, root module,
uncommitted user work and original upstream gitlink were preserved. The Gemini
SDK version remains 1.76.0; the existing macOS Keychain service/account is reused.
No API key, password, `.env` file or other credential was copied into the repo.

The original source checkout was left intact as a recovery copy. Downloaded
binaries, raw image archives/extracted files, the pre-existing root Devguard
scanner program and unrelated workspace files were not transferred. Binaries are
rebuilt in `bin/` and ignored by Git. Fresh live-run artifacts, which may include
a compiled architecture-specific probe, belong under ignored `demo/runs/`.

Docker images and containers are daemon resources, not repository files. Existing
local React demo tags/container remain available without moving them. Historical
evidence retains its original image IDs; it is not represented as a fresh Argon
or migration run. Retain the imported engine's L3montree MIT license notice.
