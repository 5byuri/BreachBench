# Gemini hardening through Antigravity

Use Gemini selected inside Antigravity to inspect this repository and invoke the existing CLI tools. Direct Gemini API access is optional and currently blocked by the supplied billing account's monthly spending cap. Do not change account billing or request credentials as part of hardening.

Work on `feat/gemini-container-hardening`. Read `hardening/README.md`, `hardening/VALIDATION.md` and current JSON evidence. Prefer current reports and tests over historical snapshots.

## Execution

Use the in-repository Container Hardening Work Bench pinned to `21f38fed9c32a39a694ba0fec32b933bfc0dbcd0`.

```powershell
node --test hardening/test/*.test.mjs
wsl -d Ubuntu -- bash hardening/wsl-run.sh run hardening/demo/config.json .breachbench/antigravity-demo
wsl -d Ubuntu -- bash hardening/wsl-run.sh slim-demo
```

The tool order is `inspect_container`, `scan_image`, `propose_hardening`, `build_candidate`, `test_application`, `verify_hardening`, `compare_results`. Antigravity supplies the agent reasoning; `run` supplies deterministic execution. Do not describe this as a validated direct-API agent run.

## Required completion work

The implementation and verification work below has now been added; read `hardening/COMPLETION.md` for commands, evidence and explicit target-host limitations. Preserve its source/profile/trace binding and truthful distinction between agent review and human approval.

- Bind security-profile review to the exact source image, profile hash and workload trace hashes. Identify agent review honestly; automated structural checks are not human permission review.
- Verify default-deny networking with explicit DNS, API and database allowances using a network-policy-capable CNI in an isolated cluster. Verify positive and negative traffic; generated manifests alone do not establish enforcement.
- Verify scoped secret injection, absence from image layers, and disabled service-account token mounts. Never read the user's account credential files.
- Generate and review AppArmor/SELinux candidates, test on a capable host, and report unsupported hosts as unverified. Do not modify the global Docker/WSL configuration to conceal missing support.
- Make finding-specific candidate changes reviewable and preserve rollback. Adapt representative tests to the selected workload rather than assuming the Python fixture represents every application.
- Fetch upstream changes regularly, integrate relevant main-branch updates without discarding local work, commit validated increments and push this feature branch. The user has authorized these pushes. Keep all code and documentation in English.

## Evidence and limits

Reports live under `.breachbench`, which is ignored by Git. Retain original image IDs and previous evidence directories. Keep image changes separate from deployment controls. A local tag derived from an ID is mutable, so preserve the identity checks before building. Hardening does not patch a vulnerable PHP/runtime or prevent all exploitation. Missing host or cluster enforcement must remain explicit in reports.
