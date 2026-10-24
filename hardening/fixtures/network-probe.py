"""Run within a selected test pod; no dependency on curl, dig or a shell."""
import errno
import os
import socket
import struct
import sys
import urllib.request

mode, host, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
if mode == 'dns':
    query_name = host
    dns = next(line.split()[1] for line in open('/etc/resolv.conf') if line.startswith('nameserver'))
    wire = b''.join(bytes([len(x)]) + x.encode() for x in query_name.split('.')) + b'\0'
    packet = struct.pack('!HHHHHH', 31337, 0x100, 1, 0, 0, 0) + wire + struct.pack('!HH', 1, 1)
    for protocol in [socket.SOCK_DGRAM, socket.SOCK_STREAM]:
        with socket.socket(socket.AF_INET, protocol) as sock:
            sock.settimeout(4)
            sock.connect((dns, 53))
            if protocol == socket.SOCK_STREAM:
                sock.sendall(struct.pack('!H', len(packet)) + packet)
                prefix = sock.recv(2)
                assert len(prefix) == 2
                result = sock.recv(struct.unpack('!H', prefix)[0])
            else:
                sock.send(packet)
                result = sock.recv(4096)
            ident, flags, questions, answers = struct.unpack('!HHHH', result[:8])
            assert ident == 31337 and flags & 15 == 0 and answers > 0
elif mode == 'denied':
    try:
        with socket.create_connection((host, port), 3):
            raise AssertionError('Connection unexpectedly allowed')
    except OSError as error:
        assert isinstance(error, TimeoutError) or error.errno in [errno.EACCES, errno.EPERM, errno.ENETUNREACH, errno.EHOSTUNREACH], repr(error)
elif mode == 'database':
    token = open('/run/secrets/database/token', 'rb').read().strip()
    for credential, expected in [(b'wrong-test-credential', b'DENIED'), (token, b'db-ok')]:
        with socket.create_connection((host, port), 4) as sock:
            sock.sendall(credential + b'\n')
            assert sock.recv(128) == expected
elif mode == 'http':
    assert urllib.request.urlopen(f'http://{host}:{port}/', timeout=4).status == 200
elif mode == 'connected':
    with socket.create_connection((host, port), 4):
        pass
elif mode == 'secrets':
    assert not os.path.exists('/var/run/secrets/kubernetes.io/serviceaccount/token')
    assert os.stat('/run/secrets/database/token').st_mode & 0o777 == 0o440
    assert os.access('/run/secrets/database/token', os.R_OK)
    try:
        open('/run/secrets/database/token', 'wb')
        raise AssertionError('Secret volume writable')
    except OSError as error:
        assert error.errno in [errno.EROFS, errno.EACCES]
else:
    raise ValueError(mode)
print('PASS')
