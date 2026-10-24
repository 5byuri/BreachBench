"""Search all saved image objects, including gzip-compressed layers, for a test canary."""
import gzip
import json
import tarfile
import sys

needle = open(sys.argv[2], 'rb').read()
assert len(needle) >= 32
def absent(stream):
    tail = b''
    while True:
        chunk = stream.read(1024 * 1024)
        if not chunk:
            return
        data = tail + chunk
        assert needle not in data, 'Runtime canary found in image object'
        tail = data[-len(needle):]
with tarfile.open(sys.argv[1]) as image:
    for member in image:
        if not member.isfile():
            continue
        with image.extractfile(member) as stream:
            magic = stream.read(4)
            stream.seek(0)
            assert magic != b'\x28\xb5\x2f\xfd', 'Zstd image object requires an explicit decoder; cannot claim layer scan coverage'
            if magic[:2] == b'\x1f\x8b':
                with gzip.GzipFile(fileobj=stream) as decompressed:
                    absent(decompressed)
            else:
                absent(stream)
print(json.dumps({'runtimeSecretAbsentFromAllImageObjects': True}))
