import ipaddress
import sys
from urllib.parse import urlsplit

host, port_raw, path, url = sys.argv[1:5]
try:
    address = ipaddress.ip_address(host)
    port = int(port_raw)
    if str(address) != host or not 1 <= port <= 65535:
        raise ValueError
    if (
        not path.startswith('/')
        or path.startswith('//')
        or any(character.isspace() for character in path)
        or '\\' in path
        or '?' in path
        or '#' in path
    ):
        raise ValueError
    expected_host = f'[{host}]' if ':' in host else host
    expected_url = f'http://{expected_host}:{port}{path}'
    parsed = urlsplit(url)
    if (
        url != expected_url
        or parsed.scheme != 'http'
        or parsed.hostname != host
        or parsed.port != port
        or parsed.path != path
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError
except (TypeError, ValueError, IndexError):
    raise SystemExit(1)
