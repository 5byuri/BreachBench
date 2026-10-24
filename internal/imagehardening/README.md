# Supplied-image hardening engine

Migrated from the working tree of L3montree's Container Hardening Work Bench on
2026-10-24 (base commit `a4def01` plus the subsequent generic-image/tool workflow).
The accompanying [MIT license](LICENSE.md) preserves the upstream attribution.

All engine code and tests were retained, with only the root Go package changed
from `main` to `imagehardening` and a small exported `Run` entry point added. The
embedded standalone probe remains `package main`. The engine lives in this Go
module; it does not call the old repository or its binary.

The old pre-existing root Devguard scanner program, its downloaded executable,
raw extracted image files, `.env` files, credentials and compiled binaries were
not imported. The bounded `harden scan` wrapper remains available. The existing
BreachBench hardening, tracing and scraping packages remain separate and intact.

Use the main BreachBench CLI's `harden auto` or `harden agent` commands, or
`harden image ACTION` for the complete imported command namespace. See
[the usage guide](../../docs/image-hardening.md).
