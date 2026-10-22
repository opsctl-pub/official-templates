import hashlib
import sys

value = open(sys.argv[1], 'rb').read()
name = b'dns-challenge-token'
digest = hashlib.sha256()
digest.update(b'opsctl-file-secret:1\0')
digest.update(len(name).to_bytes(2, 'big'))
digest.update(name)
digest.update(len(value).to_bytes(8, 'big'))
digest.update(value)
if digest.hexdigest() != sys.argv[2]:
    raise SystemExit(2)
