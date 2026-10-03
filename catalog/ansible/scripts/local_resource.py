"""Closed managed local Volume/Network actuator; never delete or adopt data."""
import argparse
import base64
import contextlib
import fcntl
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
from uuid import UUID


PROTOCOL = "opsctl-local-resource/1"
LABEL = "com.opsctl."


class ResourceError(Exception):
    """Only fixed safe codes are returned, never native output or exceptions."""


def validate(request):
    """Bounded closed request, with immutable backend-derived native identity."""
    required = {"protocol", "kind", "action", "organization_id", "resource_id", "server_id", "generation"}
    allowed = required | {"backing_id", "requested_bytes", "expected_incarnation"}
    if not isinstance(request, dict) or set(request) - allowed or not required <= set(request):
        raise ResourceError("local_resource_invalid_request")
    if request["protocol"] != PROTOCOL or request["kind"] not in {"Volume", "Network"}:
        raise ResourceError("local_resource_invalid_request")
    if request["action"] not in {"create", "observe", "delete"}:
        raise ResourceError("local_resource_invalid_request")
    for name in ("organization_id", "resource_id", "server_id"):
        value = request[name]
        if not isinstance(value, str) or str(UUID(value)) != value:
            raise ResourceError("local_resource_invalid_request")
    generation = request["generation"]
    if type(generation) is not int or not 0 < generation <= 2147483647:
        raise ResourceError("local_resource_invalid_request")
    incarnation = request.get("expected_incarnation")
    if incarnation is not None and (not isinstance(incarnation, str) or not incarnation or len(incarnation) > 128):
        raise ResourceError("local_resource_invalid_request")
    if request["kind"] == "Volume":
        if request["action"] == "delete":
            raise ResourceError("local_volume_retained")
        if not isinstance(request.get("backing_id"), str) or str(UUID(request["backing_id"])) != request["backing_id"]:
            raise ResourceError("local_resource_invalid_request")
        requested = request.get("requested_bytes")
        if requested is not None and (type(requested) is not int or requested <= 0):
            raise ResourceError("local_resource_invalid_request")
    elif request.get("backing_id") is not None or request.get("requested_bytes") is not None:
        raise ResourceError("local_resource_invalid_request")
    if request["kind"] == "Network" and request["action"] == "delete" and (
        not isinstance(incarnation, str) or not re.fullmatch(r"[a-f0-9]{64}", incarnation)
    ):
        raise ResourceError("local_network_delete_identity_required")


def locator(request):
    """No caller-provided native name, Docker data-root path or driver options."""
    prefix = "vol" if request["kind"] == "Volume" else "net"
    return ("opsctl-" + prefix + "-" + UUID(request["organization_id"]).hex + "-"
            + UUID(request["resource_id"]).hex + "-g" + str(request["generation"]))


def labels(request):
    """Exact org/resource/backing generation; display names are not ownership."""
    result = {LABEL + "managed": "true", LABEL + "org_id": request["organization_id"],
              LABEL + "resource_kind": request["kind"], LABEL + "resource_id": request["resource_id"],
              LABEL + "server_id": request["server_id"], LABEL + "generation": str(request["generation"])}
    if request["kind"] == "Volume":
        result[LABEL + "volume_id"] = request["resource_id"]
        result[LABEL + "backing_id"] = request["backing_id"]
    return result


def invoke(docker, argv):
    """Native argv and bounded attempt; stderr can contain no public diagnostics."""
    try:
        with tempfile.TemporaryFile() as output:
            child = subprocess.Popen([docker, *argv], stdout=output, stderr=subprocess.DEVNULL, env={})
            deadline = time.monotonic() + 20
            try:
                while child.poll() is None:
                    if os.fstat(output.fileno()).st_size > 65536:
                        raise ResourceError("local_resource_observation_limit")
                    if time.monotonic() >= deadline:
                        raise ResourceError("local_resource_unavailable")
                    time.sleep(0.05)
                if os.fstat(output.fileno()).st_size > 65536:
                    raise ResourceError("local_resource_observation_limit")
                output.seek(0)
                result = subprocess.CompletedProcess([docker, *argv], child.returncode, output.read())
            finally:
                if child.poll() is None:
                    child.kill()
                child.wait()
    except (OSError, subprocess.TimeoutExpired):
        raise ResourceError("local_resource_unavailable") from None
    if len(result.stdout) > 65536:
        raise ResourceError("local_resource_observation_limit")
    return result


def observe(docker, request):
    """Inspect minimal allocation identity and attachment count, not workload data."""
    name = locator(request)
    family = "volume" if request["kind"] == "Volume" else "network"
    # A missing object is distinct from an inaccessible daemon or bad inspect.
    listed = invoke(docker, [family, "ls", "--format", "{{.Name}}", "--filter", "name=^" + name + "$"])
    if listed.returncode:
        raise ResourceError("local_resource_unavailable")
    if name not in listed.stdout.decode().splitlines():
        return None
    template = ('[{{json .Name}},{{json .Driver}},{{json .Labels}},{{json .CreatedAt}},'
                '{{json .Scope}},{{json .Options}}]'
                if family == "volume" else
                '[{{json .Name}},{{json .Driver}},{{json .Labels}},{{json .Id}},'
                '{{json .Scope}},{{json .Internal}},{{len .Containers}}]')
    inspected = invoke(docker, [family, "inspect", "--format", template, "--", name])
    if inspected.returncode:
        raise ResourceError("local_resource_observation_unknown")
    try:
        value = json.loads(inspected.stdout)
    except (ValueError, UnicodeError):
        raise ResourceError("local_resource_observation_unknown") from None
    size = 6 if family == "volume" else 7
    if (not isinstance(value, list) or len(value) != size or value[0] != name
            or value[1] != ("local" if family == "volume" else "bridge")
            or value[2] != labels(request) or not isinstance(value[3], str) or not value[3]):
        raise ResourceError("local_resource_identity_mismatch")
    if family == "volume" and (value[4] != "local" or value[5] not in (None, {})):
        raise ResourceError("local_resource_identity_mismatch")
    if family == "network" and (
        not re.fullmatch(r"[0-9a-f]{64}", value[3]) or value[4] != "local"
        or value[5] is not False or type(value[6]) is not int or value[6] < 0
    ):
        raise ResourceError("local_resource_identity_mismatch")
    if request.get("expected_incarnation") is not None and value[3] != request["expected_incarnation"]:
        raise ResourceError("local_resource_incarnation_changed")
    return {"incarnation": value[3], "attachment_count": value[6] if family == "network" else None}


def capacity(docker, request, identity):
    """Bounded no-follow accounting on Docker's verified local allocation only."""
    template = '[{{json .Mountpoint}},{{json .CreatedAt}},{{json .Labels}}]'
    result = invoke(docker, ["volume", "inspect", "--format", template, "--", locator(request)])
    if result.returncode:
        raise ResourceError("local_resource_observation_unknown")
    try:
        path, incarnation, owner = json.loads(result.stdout)
    except (ValueError, TypeError, UnicodeError):
        raise ResourceError("local_resource_observation_unknown") from None
    if (incarnation != identity["incarnation"] or owner != labels(request)
            or not isinstance(path, str) or not os.path.isabs(path)):
        raise ResourceError("local_resource_identity_mismatch")
    descriptors = []
    try:
        root = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        descriptors.append(root)
        filesystem = os.fstatvfs(root)
        free = filesystem.f_bavail * filesystem.f_frsize
        used, entries, visited = 0, 0, set()
        deadline = time.monotonic() + 2
        pending = [root]
        while pending:
            current = pending.pop()
            with os.scandir(current) as children:
                for entry in children:
                    entries += 1
                    if entries > 100000 or time.monotonic() >= deadline:
                        return {"observed_used_bytes": None, "observed_free_bytes": free}
                    metadata = entry.stat(follow_symlinks=False)
                    key = (metadata.st_dev, metadata.st_ino)
                    if key in visited:
                        continue
                    visited.add(key)
                    if stat.S_ISREG(metadata.st_mode):
                        used += metadata.st_blocks * 512
                    elif stat.S_ISDIR(metadata.st_mode):
                        if len(pending) >= 256:
                            return {"observed_used_bytes": None, "observed_free_bytes": free}
                        child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                        dir_fd=current)
                        descriptors.append(child)
                        pending.append(child)
            if current != root:
                os.close(current)
                descriptors.remove(current)
        if observe(docker, request) != identity:
            raise ResourceError("local_resource_incarnation_changed")
        return {"observed_used_bytes": used, "observed_free_bytes": free}
    except OSError:
        return {"observed_used_bytes": None, "observed_free_bytes": None}
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


@contextlib.contextmanager
def exclusion(request):
    """Use the same native-resource exclusion as shared Compose transitions."""
    root = "/run/lock/opsctl-compose"
    os.makedirs(root, mode=0o700, exist_ok=True)
    family = "volume" if request["kind"] == "Volume" else "network"
    identity = request["backing_id"] if family == "volume" else request["resource_id"]
    descriptor = os.open(root + "/" + family + "-" + UUID(identity).hex,
                         os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    deadline = time.monotonic() + 60
    try:
        while True:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise ResourceError("local_resource_lock_timeout")
                time.sleep(0.05)
        yield
    finally:
        os.close(descriptor)


def execute(request):
    """Idempotent exact create/observe and empty-network removal; no Volume rm."""
    validate(request)
    with exclusion(request):
        return execute_locked(request)


def execute_locked(request):
    """Observe and act only while the exact allocation cannot be transitioned."""
    docker = shutil.which("docker")
    if not docker:
        raise ResourceError("local_resource_docker_unavailable")
    before = observe(docker, request)
    changed = False
    family = "volume" if request["kind"] == "Volume" else "network"
    if before is None and request["action"] == "create":
        if request.get("expected_incarnation") is not None:
            raise ResourceError("local_resource_incarnation_missing")
        argv = [family, "create", "--driver", "local" if family == "volume" else "bridge"]
        for key, value in sorted(labels(request).items()):
            argv.extend(["--label", key + "=" + value])
        argv.append(locator(request))
        result = invoke(docker, argv)
        after = observe(docker, request)
        if after is None:
            raise ResourceError("local_resource_observation_unknown")
        before = after
        changed = result.returncode == 0
    elif before is not None and request["action"] == "delete":
        if before["attachment_count"] != 0:
            raise ResourceError("local_network_in_use")
        result = invoke(docker, ["network", "rm", "--", before["incarnation"]])
        if result.returncode:
            raise ResourceError("local_network_removal_unknown")
        if observe(docker, request) is not None:
            raise ResourceError("local_resource_incarnation_changed")
        before = None
        changed = True
    accounting = capacity(docker, request, before) if family == "volume" and before else {}
    if accounting and observe(docker, request) != before:
        raise ResourceError("local_resource_incarnation_changed")
    return {"protocol": PROTOCOL, "kind": request["kind"], "organization_id": request["organization_id"],
            "resource_id": request["resource_id"], "server_id": request["server_id"],
            "generation": request["generation"], "presence": "present" if before else "absent",
            "incarnation": before["incarnation"] if before else None,
            "attachment_count": before["attachment_count"] if before else 0,
            "driver": "local" if family == "volume" else "bridge", "quota_enforced": False,
            "changed": changed, **accounting}


def main():
    """Ansible supplies only a serialized closed identity contract."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True)
    args = parser.parse_args()
    try:
        if len(args.request) > 16384:
            raise ResourceError("local_resource_invalid_request")
        request = json.loads(base64.b64decode(args.request, validate=True))
        output = execute(request)
    except ResourceError as error:
        print(json.dumps({"error_code": str(error)}))
        return 1
    except (ValueError, TypeError, UnicodeError):
        print(json.dumps({"error_code": "local_resource_invalid_request"}))
        return 1
    except OSError:
        print(json.dumps({"error_code": "local_resource_unavailable"}))
        return 1
    print(json.dumps(output, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
