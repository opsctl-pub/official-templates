"""Bounded HTTP/TLS request and gateway telemetry observation, without inspection."""

import base64
import hashlib
import http.client
import ipaddress
import json
import os
import re
import secrets
import selectors
import signal
import socket
import ssl
import subprocess
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit


def timestamp():
    """Return the actual observation time."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def empty_facts(kind):
    """Distinguish unavailable observations from negative observations."""
    return {
        "outcome": "incomplete", "observed_at": timestamp(), "kind": kind,
        "passed": False, "status": None, "body_match": None,
        "gateway_container_id": None, "router_name": None, "upstream": None,
        "container_id": None, "image_id": None, "started_at": None,
        "tls": None, "destination": None, "origin_tls_observed": None,
        "cache_headers": None,
    }


def validate(request):
    """Validate only the request primitive's bounded native inputs."""
    kind, target = request["verification_kind"], request["verification_target"]
    if kind not in {"gateway", "public_edge"} or not isinstance(target, dict):
        raise ValueError
    if not re.fullmatch(r"[a-f0-9]{64}", request["gateway_container_id"]):
        raise ValueError
    for name in ("container_port", "gateway_port", "expected_status"):
        value = target[name]
        low, high = (100, 599) if name == "expected_status" else (1, 65535)
        if type(value) is not int or not low <= value <= high:
            raise ValueError
    path, needle, host = target["path"], target["body_contains"], target["host"]
    if (not isinstance(path, str) or not path.startswith("/") or path.startswith("//")
            or len(path.encode()) > 1024 or any(c.isspace() or c in "\\?#" for c in path)
            or not isinstance(host, str) or len(host) > 253
            or not re.fullmatch(r"[a-z0-9.-]+", host)
            or not isinstance(target["router_name"], str)
            or not 1 <= len(target["router_name"]) <= 128
            or (needle is not None and (
                not isinstance(needle, str) or len(needle.encode()) > 1024))):
        raise ValueError
    backend = urlsplit(target["backend_url"])
    address = ipaddress.ip_address(backend.hostname)
    if (backend.scheme != "http" or not backend.port or backend.path or backend.query
            or backend.fragment or backend.username or backend.password
            or address.is_unspecified or address.is_multicast
            or not (address.is_private or address.is_loopback)):
        raise ValueError
    if kind == "public_edge":
        destination = ipaddress.ip_address(target["destination"])
        if not destination.is_global or destination.is_multicast:
            raise ValueError
        names = target["cache_header_names"]
        if (not isinstance(names, list) or len(names) > 64 or len(set(names)) != len(names)
                or any(not isinstance(name, str)
                       or not re.fullmatch(r"[a-zA-Z0-9-]{1,128}", name) for name in names)):
            raise ValueError
    return kind, target


def request_once(kind, target, marker, facts):
    """Make one direct request with no proxy or redirect handling."""
    def timeout(_signum, _frame):
        raise TimeoutError

    if kind == "public_edge":
        connection = http.client.HTTPSConnection(
            target["host"], timeout=6, context=ssl.create_default_context(),
        )
        connection._create_connection = lambda unused, timeout, source_address: socket.create_connection(
            (target["destination"], 443), timeout, source_address,
        )
    else:
        connection = http.client.HTTPConnection("127.0.0.1", target["gateway_port"], timeout=6)
    previous_handler = signal.signal(signal.SIGALRM, timeout)
    signal.setitimer(signal.ITIMER_REAL, 6)
    try:
        connection.connect()
        if kind == "public_edge":
            certificate = connection.sock.getpeercert(binary_form=True)
            if not certificate or len(certificate) > 65536:
                raise ValueError
            facts["tls"] = {
                "status": "verified",
                "leaf_fingerprint_sha256": hashlib.sha256(certificate).hexdigest(),
            }
            facts["destination"] = connection.sock.getpeername()[0]
        connection.request("GET", target["path"], headers={
            "Host": target["host"], "X-Opsctl-Request-Id": marker,
            "Cache-Control": "no-cache, no-store",
        })
        response = connection.getresponse()
        facts["status"] = response.status
        body = response.read(65537)
        if len(body) > 65536:
            raise ValueError
        needle = target["body_contains"]
        facts["body_match"] = needle is None or needle in body.decode("utf-8", errors="replace")
        if kind == "public_edge":
            headers = {}
            for name in target["cache_header_names"]:
                values = response.headers.get_all(name, [])
                if len(values) != 1 or len(values[0].encode()) > 128:
                    raise ValueError
                headers[name] = values[0]
            facts["cache_headers"] = headers
    except ssl.SSLError:
        if kind == "public_edge":
            facts["tls"] = {"status": "failed", "leaf_fingerprint_sha256": None}
        raise
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous_handler)
        connection.close()


def telemetry(container_id, since, marker):
    """Read at most 256 native log entries and 64 KiB, never inspect Docker."""
    with subprocess.Popen(
        ["docker", "logs", "--since", since, "--tail", "256", container_id],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    ) as process:
        output = bytearray()
        deadline = time.monotonic() + 6
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        raise ValueError
                    chunk = os.read(process.stdout.fileno(), min(4096, 65537 - len(output)))
                    if not chunk:
                        break
                    output.extend(chunk)
                    if len(output) > 65536:
                        raise ValueError
            process.wait(timeout=max(0, deadline - time.monotonic()))
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
        if process.returncode or len(output) > 65536:
            raise ValueError
    lines = output.splitlines()
    if len(lines) > 256:
        raise ValueError
    matches = []
    for line in lines:
        try:
            entry = json.loads(line)
        except (ValueError, UnicodeDecodeError):
            continue
        if isinstance(entry, dict) and entry.get("request_X-Opsctl-Request-Id") == marker:
            matches.append(entry)
    if len(matches) != 1:
        raise ValueError
    return matches[0]


def safe_upstream(value):
    """Return only a canonical private HTTP endpoint safe to retain as a fact."""
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        return None
    try:
        parsed = urlsplit(value)
        if (parsed.scheme != "http" or parsed.username is not None
                or parsed.password is not None or parsed.path or parsed.query
                or parsed.fragment or parsed.hostname is None
                or parsed.port is None or not 1 <= parsed.port <= 65535):
            return None
        address = ipaddress.ip_address(parsed.hostname)
        if (address.is_unspecified or address.is_multicast
                or not (address.is_private or address.is_loopback)):
            return None
        host = f"[{address}]" if address.version == 6 else str(address)
        if value != f"http://{host}:{parsed.port}":
            return None
    except ValueError:
        return None
    return value


def probe(request):
    """Require one correlated native observation for each bounded attempt."""
    kind, target = validate(request)
    code = "verification_failed"
    facts = empty_facts(kind)
    for attempt in range(10):
        code = "verification_failed"
        facts = empty_facts(kind)
        facts["gateway_container_id"] = request["gateway_container_id"]
        marker, since = secrets.token_hex(16), timestamp()
        try:
            request_once(kind, target, marker, facts)
            code = "verification_upstream_unverified"
            entry = telemetry(request["gateway_container_id"], since, marker)
            router, upstream = entry.get("RouterName"), entry.get("ServiceURL")
            if isinstance(router, str) and 1 <= len(router) <= 128:
                facts["router_name"] = router
            facts["upstream"] = safe_upstream(upstream)
            if (router != target["router_name"] or facts["upstream"] is None
                    or facts["upstream"] != target["backend_url"]
                    or type(entry.get("OriginStatus")) is not int
                    or entry["OriginStatus"] != facts["status"]
                    or type(entry.get("DownstreamStatus")) is not int
                    or entry["DownstreamStatus"] != facts["status"]
                    or entry.get("RequestHost") != target["host"]
                    or entry.get("RequestMethod") != "GET"
                    or entry.get("RequestPath") != target["path"]):
                raise ValueError
            if kind == "public_edge":
                version = entry.get("TLSVersion")
                facts["origin_tls_observed"] = version in {"1.2", "1.3"} if version else None
                if facts["origin_tls_observed"] is not True:
                    raise ValueError
            code = "verification_failed"
            if facts["status"] != target["expected_status"] or facts["body_match"] is not True:
                raise ValueError
            facts.update(outcome="succeeded", passed=True, observed_at=timestamp())
            return {"deployment_verification": facts}
        except FileNotFoundError:
            facts["outcome"] = "incomplete"
            facts["observed_at"] = timestamp()
            return {"deployment_verification": facts, "procedure_error": {
                "phase": "observe", "code": "native_tool_unavailable",
            }}
        except (ValueError, OSError, http.client.HTTPException, subprocess.SubprocessError):
            facts["observed_at"] = timestamp()
            if attempt < 9:
                time.sleep(3)
    facts["outcome"] = "failed"
    return {"deployment_verification": facts, "procedure_error": {"phase": "probe", "code": code}}


def main():
    """Emit only plain observations and a closed failure code."""
    result = {
        "deployment_verification": empty_facts("gateway"),
        "procedure_error": {"phase": "validate", "code": "routing_input_invalid"},
    }
    try:
        raw = base64.b64decode(sys.argv[1], validate=True)
        if len(raw) > 262144:
            raise ValueError
        result = probe(json.loads(raw))
    except (ValueError, KeyError, TypeError, IndexError):
        pass
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result["deployment_verification"]["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
