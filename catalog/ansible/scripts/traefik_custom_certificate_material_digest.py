import hashlib
import sys
from pathlib import Path
digest = hashlib.sha256(b'opsctl-file-secret:1\0')
for name in ('tls.crt', 'tls.key'):
    path = Path(sys.argv[1]) / name
    with path.open('rb') as stream:
        value = stream.read(262145)
    if not value or len(value) > 262144:
        raise SystemExit(2)
    encoded = name.encode('ascii')
    digest.update(len(encoded).to_bytes(2, 'big'))
    digest.update(encoded)
    digest.update(len(value).to_bytes(8, 'big'))
    digest.update(value)
if digest.hexdigest() != sys.argv[2]:
    raise SystemExit(2)
