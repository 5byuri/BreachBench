# Local bank demo: all commands

Verified 25 October 2026. This guide records a real deterministic-tools run, not
a live Argon run. Dockerfile input is not yet supported by the simple CLI: you
build the original image, then pass its image name to BreachBench.

## Already running now

| | Original | Hardened |
| --- | --- | --- |
| Website | http://127.0.0.1:3000 | http://127.0.0.1:3001 |
| Container | `breachbench-react-demo-before` | `breachbench-demo-after` |
| HTTP / health | 200 / healthy | 200 / healthy |
| UID:GID | 0:0 | 65532:65532 |
| `/bin/sh -c id` | succeeds | fails: missing `/bin/sh` (exit 126) |
| Exclusive temporary `/etc` write | allowed; probe removed | denied: EROFS |
| `apt-get --version` | available | missing: ENOENT |

Both containers use `network=none`; neither publishes Docker ports. Their host
forwarders listen on IPv4 loopback only. Existing unrelated demo containers were
not stopped or replaced. Do not rerun a start command with an already-used name
or start another forwarder on an occupied port.

## 1. Build the binaries and original image, if needed

```sh
cd /Users/larshermges/Documents/projects/github/byuri/own/BreachBench
go build -o bin/breachbench .
go build -o bin/react-demo-web ./cmd/react-demo-web
docker build -f fixtures/react2shell/Containerfile -t local/react2shell:british-bank-demo fixtures/react2shell
```

The existing original image was reused for the verified run; it was not rebuilt
or overwritten. Both its running container and the hardener's source resolve to
`sha256:27b68f7aca777347395493b6718441912bb2ac6ac2c3f9313eba3ee301759ffd`.

## 2. Start the original (skip: already running)

```sh
docker run -d --rm --name breachbench-react-demo-before \
  --network=none --memory=512m --cpus=1 --pids-limit=128 \
  local/react2shell:british-bank-demo
```

In a separate terminal, keep the local forwarder running:

```sh
./bin/react-demo-web --container breachbench-react-demo-before --port 3000
```

Open http://127.0.0.1:3000. Docker starts the image's Node ENTRYPOINT/CMD;
`docker exec` is not needed to start the server.

## 3. Harden one image

```sh
./bin/breachbench local/react2shell:british-bank-demo --mode tools
```

No workload/policy JSON or temporary-directory variables are needed. The CLI
prints detected findings, progress, actual removed entries, a new image tag,
the protected Docker command and the evidence directory. The verified run
removed 11 tool entries and created `breachbench/hardened:613b542207e9` with
evidence in `demo/runs/image-613b542207e9/`.

Each new run prints its own fresh tag. **If you run hardening again, use that new
printed tag in the next command.** The tag below is the actual verified image
already present on this Mac.

For a live Argon run using existing Gemini environment/Keychain credentials,
omit `--mode tools`. No live model call was made for this demonstration.

## 4. Start the hardened candidate (skip: already running)

```sh
docker run -d --rm --name breachbench-demo-after \
  --pull=never --user=65532:65532 --read-only \
  --cap-drop=ALL --security-opt=no-new-privileges:true \
  --network=none --memory=512m --cpus=1 --pids-limit=128 \
  --tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777 \
  breachbench/hardened:613b542207e9
```

In another terminal, keep the second forwarder running:

```sh
./bin/react-demo-web --container breachbench-demo-after --port 3001
```

Open http://127.0.0.1:3001. Do not append Docker flags to the generated `run.sh`:
it appends arguments after the image, where they are application arguments.

## 5. Show the difference in a third terminal

Identity (Node remains available even though `whoami` need not be retained):

```sh
docker exec breachbench-react-demo-before node -e 'console.log(process.getuid())'
docker exec breachbench-demo-after node -e 'console.log(process.getuid())'
```

Shell: the first succeeds; the second deliberately fails because `/bin/sh` is
missing. Both websites remain running.

```sh
docker exec breachbench-react-demo-before /bin/sh -c 'id'
docker exec breachbench-demo-after /bin/sh -c 'id'
```

For an interactive original shell, use this command and type `exit` afterward:

```sh
docker exec -it breachbench-react-demo-before /bin/sh
```

System write: the original creates and removes an exclusive probe; the hardened
container fails at creation with EROFS. The `wx` flag prevents overwriting an
existing file.

```sh
docker exec breachbench-react-demo-before node -e 'const f=require("node:fs"),p="/etc/breachbench-demo-"+Date.now();f.writeFileSync(p,"demo",{flag:"wx"});f.unlinkSync(p);console.log("write allowed; probe removed")'
docker exec breachbench-demo-after node -e 'const f=require("node:fs"),p="/etc/breachbench-demo-"+Date.now();f.writeFileSync(p,"demo",{flag:"wx"});f.unlinkSync(p);console.log("write allowed; probe removed")'
```

Package-manager entrypoint: the original reports its version; the hardened
container reports a missing executable. No package installation is attempted.

```sh
docker exec breachbench-react-demo-before /usr/bin/apt-get --version
docker exec breachbench-demo-after /usr/bin/apt-get --version
```

Check that both applications still respond:

```sh
curl --noproxy '*' --fail http://127.0.0.1:3000/api/health
curl --noproxy '*' --fail http://127.0.0.1:3001/api/health
```

## Stop only this new candidate when finished

```sh
docker stop breachbench-demo-after
```

Its `--rm` removes that disposable container. The image and evidence remain.
Its forwarder exits when the container stops. The pre-existing baseline and old
hardened demo are left untouched; Ctrl+C stops a forwarder without stopping its
app container.

## Scope and safety

These checks are not an exploit or proof that React2Shell is patched. Retained
application/runtime versions are unchanged; arbitrary Node execution is still
possible if the application is exploited. The smoke checks cover these endpoints
and controls only, not every application feature or network-exfiltration path.
The original static report correctly remains `application_tested:false`; the
separate `live-verification.json` records the later demo checks.

The forwarder is fixture-specific and uses Node through `docker exec`, without
a shell, host application mounts or Docker-published ports. On this Docker
27.5.1 host, `--demo` publishing is intentionally refused: Docker documents that
pre-28 localhost-published ports can be reachable from the same L2 network.
See https://docs.docker.com/engine/network/port-publishing/ .
