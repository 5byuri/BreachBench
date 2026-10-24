# Local containment demo

From the repository root, with Docker running and Go installed:

```sh
go run . harden demo /absolute/path/to/new-demo-results
```

The output directory must not exist. Its parent must exist. Allow up to 20 minutes for the first image pulls and builds; adjust `--timeout` if needed. Open `report.html` after the command finishes. `results.json`, `before.json`, `after.json`, `baseline-recheck.json`, `run.log`, and `hardened/verification.json` contain the evidence. Failed runs exit nonzero and produce a report explicitly marked **NOT PROVEN**. Never treat missing observations as blocked attacks.

The fixture is a deliberately vulnerable Node application that evaluates an HTTP request's code. It is synthetic training code, not PHP2Shell or React2Shell. Its endpoint binds only to container loopback. The runner publishes no host ports, mounts no host data into the vulnerable container, supplies only a dummy secret, and creates an internal Docker network with a local HTTP sink. Images may require internet access during builds; runtime probes use only the internal network. The runner removes its containers and network even after failures. Built images and evidence remain for inspection. Forced process termination or Docker outages can prevent cleanup.

The runner records the baseline image ID, tests it, builds the same source with BreachBench's Node hardener, verifies the runtime, and repeats exactly the same HTTP requests. The client runs through `docker exec` only to reach loopback; each exploit observation comes from the application's HTTP response, not direct client filesystem or shell access. A fresh random challenge ties responses to this run. The baseline is tested again afterward so a failed sink cannot masquerade as successful egress containment.

| Probe | Baseline required | Hardened required |
|---|---|---|
| Code execution with fresh challenge | Succeeds | Still succeeds |
| `/bin/sh` printing challenge | Succeeds | ENOENT |
| Application directory write/read | Succeeds | EROFS |
| Root filesystem write/read | Succeeds | EROFS |
| `/tmp` write/read | Succeeds | Still succeeds |
| Worker dummy secret read | Succeeds | Still succeeds |
| HTTP connection to controlled sink | Succeeds | Network failure |

The hardened image inventory and separate runtime probe also check known shell/downloader/package-manager names, setuid/setgid files, non-root UID, dropped capabilities, no-new-privileges, read-only root, active seccomp, and rejection of `ptrace`, `mount`, and `bpf` syscall probes. These checks are recorded individually. They do not prove that seccomp alone caused each rejection; multiple controls overlap.

This demonstrates containment under Docker `network=none`, not Kubernetes CNI enforcement, an egress allowlist, real external credential scoping, every application workflow, or removal of arbitrary code execution. The vulnerable worker can still read its own data and return it through application responses. Writable temporary storage is intentional. Patch or remove the unsafe evaluation to fix the vulnerability.
