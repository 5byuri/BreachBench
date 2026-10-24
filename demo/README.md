# Local container-hardening demo

The public fixtures live in [`../fixtures/`](../fixtures/). Start with [The British Bank browser demo](../docs/react2shell-browser-demo.md): a fictional GBP dashboard with a real transfer-preview Server Action, no banking connection, and localhost-only access.

The [British Bank evidence](evidence/british-bank-2026-10-24/) records a fresh successful Argon hardening run by BreachBench and normal browser-form checks before/after hardening. Other evidence below is historical, copied from earlier workbench runs and labelled separately.

**The React2Shell fixture is deliberately vulnerable. Never expose it publicly, supply real credentials or sensitive host mounts, or deploy it in production.** Hardening does not patch its affected Next.js/RSC implementation or establish that arbitrary JavaScript execution is prevented.

## Start the unhardened application safely

From the repository root, build the real Next.js App Router fixture if its local image is missing:

```sh
docker build -f fixtures/react2shell/Containerfile \
  -t local/react2shell:unhardened fixtures/react2shell
```

Start its original entrypoint with networking disabled and no published ports:

```sh
docker run --detach --rm --name breachbench-react-unhardened \
  --network none --memory 512m --cpus 1 --pids-limit 128 \
  local/react2shell:unhardened
```

After startup, check the actual service over container loopback. This manual check uses the fixture's existing Node runtime; the generic CLI's checker does not depend on an in-image Node installation.

```sh
docker exec breachbench-react-unhardened node -e \
  'fetch("http://127.0.0.1:3000/api/health").then(async r => { if (r.status !== 200) throw Error("health failed"); console.log(await r.text()); }).catch(e => { console.error(e.message); process.exitCode = 1; })'
docker rm -f breachbench-react-unhardened
```

No network ports are opened on the host. The default root user and application dependencies are not changed by this smoke test. Use a different container name if the example name is already in use; remove only the container you created.

## Run a fresh before/after comparison

The deterministic path runs the dedicated local tools without a model request:

```sh
mkdir -p demo/runs
go run . harden auto --mode tools \
  --image local/react2shell:unhardened \
  --target local/react2shell:demo-new \
  --checks fixtures/react2shell/workload.json \
  --policy fixtures/react2shell/policy.json \
  --artifacts demo/runs/react2shell-new
```

Choose a new target tag and artifact directory for each run. Read the new `comparison.md` and `report.json`, and keep `compose.json` with the resulting image: a container image alone cannot enforce read-only filesystems, writable mounts, or network restrictions. The supplied policy keeps networking disabled and permits only the declared `/tmp` and Next.js cache tmpfs paths.

The model-coordinated route uses the same flags with `harden agent --mode argon`. It requires separately configured Gemini access; never put a key in this repository or a demo command. The older archived Argon attempt returned HTTP 429. The separate British Bank report records the later successful Argon run; the historical failure is not presented as a success. Tool mode is explicit, not a silent fallback.

Fresh runs compile their own static containment checker for the Docker target architecture. That executable is deliberately not archived here. `demo/runs/` is for new local output, not historical evidence.

## Archived evidence and provenance

| Evidence | Original workspace directory | What it records |
| --- | --- | --- |
| [British Bank live Argon run](evidence/british-bank-2026-10-24/comparison.md) | BreachBench `demo/runs/british-bank-2026-10-24` | Fresh model-coordinated hardening, passing HTTP/containment checks, and a [verification record](evidence/british-bank-2026-10-24/verification.json) of fictional £25 transfer previews working before and after. |
| [Real Next.js / React2Shell](evidence/react2shell-2026-10-24/comparison.md) | `react2shell-generic-2026-10-24` | Original service checks before/after, protected writes, root-to-non-root change, six accessible tested shell paths becoming unavailable. [Verification](evidence/react2shell-2026-10-24/verification.md) also records an ordinary Server Action POST and unchanged runtime/dependency hashes. |
| [Debian batch workload](evidence/debian-2026-10-24/comparison.md) | `debian-generic-2026-10-24` | Required shells remain available for the declared batch workload; protected writes and local helper installation become denied. This is not a service-startup test. |
| [Earlier synthetic tool demo](evidence/legacy-tool-demo-2026-10-24/comparison.md) | `container-demo-2026-10-24` | A fixture-specific finite Node self-test and scripted Docker containment comparison. It is not the real Next.js example and not successful automatic Slim profiling. |
| [Argon HTTP 429](evidence/diagnostics/argon-http-429.json) | `integration-diagnostics-2026-10-24/argon-http-429.json` | The unsuccessful model request, preserved without implying a later API success. |

The original workspace parent was `/Users/larshermges/Documents/Codex/2026-08-26/okay`. Older archived Markdown/JSON files are byte-identical copies: historical image tags, image IDs, absolute artifact paths, coverage statements, and limitations have not been rewritten to match the new repository location. Embedded old paths are provenance, not promises that those directories or temporary tags still exist. The new unhardened image tag above is not substituted into old reports.

Docker owns local images independently of the repository. No image layers, containers, or Docker storage directories were moved into `demo/`; rebuilding from the fixture may produce different image IDs. There are no executable probe binaries, raw Slim logs, personal application ledgers, credentials, or raw scanner exports in the archive. Only the selected public/sanitized `.md` and `.json` artifacts were copied after a credential-pattern and text/JSON validation check.

These checks show selected workload compatibility and post-code-execution containment. They do not demonstrate complete dependency discovery, the absence of other shells or tools, network reachability measurement, a React2Shell exploit, or prevention of in-memory/runtime attacks. Writable tmpfs paths remain writable, and production vulnerabilities still require patches.
