# Supplied-image hardening comparison

Source: `local/react2shell-baseline:demo`

Hardened image: `local/react2shell-hardened:verified`

Mode: `tools`

| Check | Before | After |
|---|---|---|
| Declared application checks | passed | passed |
| Effective UID:GID | 0:0 | 65532:65532 |
| Writes to protected directories | /: allowed; /usr: allowed; /etc: allowed | /: denied; /usr: denied; /etc: denied |
| Accessible tested shell paths | 6 | 0 |
| Install benign local tool into protected root | allowed | denied |
| Retained application/runtime bytes | Original | Copied unchanged |

Required shells/tools may remain. Read-only, privilege, writable-path and network restrictions require compose.json. This does not patch React2Shell or stop arbitrary runtime code execution. No remote exploit was tested.
