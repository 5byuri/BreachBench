# Live containment comparison

| Check | Before | After |
|---|---|---|
| Original HTTP self-test | passed | passed |
| Effective UID | 0 | 65532 |
| Protected root write | allowed | denied (EROFS) |
| Tested shell execution | Available | Unavailable at all six tested paths |
| Local JS tool install into protected root | allowed | denied (EROFS) |
| Application and Node binary SHA-256 | Baseline | Identical |

These are fixed local post-compromise checks, not a remote exploit. Runtime code execution and writable-mount abuse remain possible. Use compose.json for deployment restrictions.
