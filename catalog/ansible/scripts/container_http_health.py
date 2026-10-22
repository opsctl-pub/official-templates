"""Probe an exact managed container using host tools in its network namespace."""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from urllib.parse import urlsplit
from uuid import UUID


INSPECT_FORMAT = (
    '[{{json .Id}},{{json .State.Pid}},{{json .State.Running}},'
    '{{json .State.StartedAt}},{{json (index .Config.Labels "com.opsctl.managed")}},'
    '{{json (index .Config.Labels "com.opsctl.org_id")}},'
    '{{json (index .Config.Labels "com.opsctl.deployment_id")}},'
    '{{json (index .Config.Labels "com.opsctl.revision_id")}}]'
)
HTTP_PROBE = '''import http.client, sys
connection = http.client.HTTPConnection("127.0.0.1", int(sys.argv[1]), timeout=5)
try:
    connection.request("GET", sys.argv[2])
    response = connection.getresponse()
    result = 0 if response.status == 200 else 2
except (OSError, http.client.HTTPException):
    result = 3
finally:
    connection.close()
sys.exit(result)
'''


class HealthError(Exception):
    """Fixed diagnostics only; never expose Docker metadata or response bodies."""


def validate(args):
    """Reject ambiguous names, identities and anything outside loopback HTTP."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", args.container):
        raise HealthError("container_health_invalid_input")
    if not re.fullmatch(r"[0-9]{1,5}", args.port) or not 1 <= int(args.port) <= 65535:
        raise HealthError("container_health_invalid_input")
    path = urlsplit(args.path)
    if (not args.path.startswith("/") or args.path.startswith("//")
            or len(args.path) > 2048 or path.scheme or path.netloc or path.fragment
            or any(ord(char) <= 32 or ord(char) >= 127 for char in args.path)):
        raise HealthError("container_health_invalid_input")
    for value in (args.organization, args.deployment, args.revision):
        if value and str(UUID(value)) != value:
            raise HealthError("container_health_invalid_input")
    if not args.organization:
        raise HealthError("container_health_invalid_input")


def inspect(docker, args):
    """Collect only bounded identity metadata, not configuration or secrets."""
    result = subprocess.run(
        [docker, "inspect", "--type", "container", "--format", INSPECT_FORMAT,
         "--", args.container], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=10, env={}, check=False,
    )
    if result.returncode or len(result.stdout) > 4096:
        raise HealthError("container_health_target_unavailable")
    try:
        value = json.loads(result.stdout)
    except (ValueError, UnicodeError):
        raise HealthError("container_health_target_invalid") from None
    if (not isinstance(value, list) or len(value) != 8
            or not isinstance(value[0], str) or not re.fullmatch(r"[0-9a-f]{64}", value[0])
            or type(value[1]) is not int or value[1] <= 0 or value[2] is not True
            or not isinstance(value[3], str) or not value[3]
            or value[4] != "true"
            or value[5] != args.organization
            or (value[6] or "") != args.deployment
            or (value[7] or "") != args.revision):
        raise HealthError("container_health_target_invalid")
    return value


def probe(args):
    """Pin the namespace and reject replacement before or after the request."""
    validate(args)
    nsenter = shutil.which("nsenter")
    docker = shutil.which("docker")
    if not nsenter:
        raise HealthError("container_health_nsenter_unavailable")
    if not docker:
        raise HealthError("container_health_docker_unavailable")
    before = inspect(docker, args)
    descriptor = os.open(f"/proc/{before[1]}/ns/net", os.O_RDONLY)
    try:
        if inspect(docker, args) != before:
            raise HealthError("container_health_target_changed")
        result = subprocess.run(
            [nsenter, f"--net=/proc/self/fd/{descriptor}", "--", sys.executable,
             "-I", "-c", HTTP_PROBE, args.port, args.path],
            pass_fds=(descriptor,), stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=10, env={}, check=False,
        )
        if inspect(docker, args) != before:
            raise HealthError("container_health_target_changed")
        if result.returncode:
            raise HealthError("container_health_http_failed")
    finally:
        os.close(descriptor)


def main():
    """One attempt; the Ansible owner retains its bounded retry policy."""
    parser = argparse.ArgumentParser()
    for name in ("container", "organization", "deployment", "revision", "port", "path"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        probe(args)
    except HealthError as error:
        print(json.dumps({"error_code": str(error)}))
        return 1
    except subprocess.TimeoutExpired:
        print(json.dumps({"error_code": "container_health_timeout"}))
        return 1
    except (OSError, ValueError):
        print(json.dumps({"error_code": "container_health_probe_failed"}))
        return 1
    print(json.dumps({"status": "healthy"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
