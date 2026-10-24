#!/bin/sh
set -eu
# Exercise all demo routes and confirm background work advances during tracing.
python - <<'PY'
import time
import urllib.request
import ctypes
# Retain the library needed by the separate syscall-enforcement probe.
assert ctypes.CDLL(None).getpid() > 0
for attempt in range(50):
    try:
        assert urllib.request.urlopen('http://127.0.0.1:8080/').read() == b'healthy'
        break
    except OSError:
        time.sleep(.1)
else:
    raise RuntimeError('Application did not become ready')
url = 'http://127.0.0.1:8080/jobs'
before = int(urllib.request.urlopen(url).read())
time.sleep(.5)
assert int(urllib.request.urlopen(url).read()) > before
assert urllib.request.urlopen('http://127.0.0.1:8080/rare/export').read() == b'uncommon-path-ok'
PY
