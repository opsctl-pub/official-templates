"""Bounded local Docker reads projected before leaving the selected Server."""
import argparse
from datetime import datetime, timezone
import json
import os
import re
import selectors
import shutil
import stat
import subprocess
import sys
import time


CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")
ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
SOCKET = "/var/run/docker.sock"
READ_BYTES = 1048576
READ_SECONDS = 10
TOTAL_BYTES = 33554432
TOTAL_SECONDS = 60


class Unavailable(Exception):
    """A fixed safe diagnostic, never native output."""


def problem(code, path="", fact="observation"):
    """Build only fixed safe diagnostics and caller-owned bounded paths."""
    return {"code": code, "resource_path": path, "fact": fact,
            "message": "The requested fact could not be completely observed."}


def utc_now():
    """Timestamp the actual observation, not ingestion or a host-wide snapshot."""
    return datetime.now(timezone.utc).isoformat()


class NativeReads:
    """Count both pipes while reading; terminate and reap only our CLI child."""

    def __init__(self):
        self.remaining = TOTAL_BYTES
        self.deadline = time.monotonic() + TOTAL_SECONDS

    def read(self, arguments):
        """Read one local endpoint with the remaining aggregate allowance."""
        deadline = min(self.deadline, time.monotonic() + READ_SECONDS)
        allowance = min(READ_BYTES, self.remaining)
        if allowance <= 0 or deadline <= time.monotonic():
            raise Unavailable("native_budget_exceeded")
        environment = {key: value for key, value in os.environ.items()
                       if not key.startswith("DOCKER_")}
        try:
            child = subprocess.Popen(
                ["docker", "--host", "unix://" + SOCKET, *arguments],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
            )
        except OSError:
            raise Unavailable("docker_unavailable") from None
        output = bytearray()
        consumed = 0
        try:
            with selectors.DefaultSelector() as poller:
                poller.register(child.stdout, selectors.EVENT_READ, True)
                poller.register(child.stderr, selectors.EVENT_READ, False)
                while poller.get_map():
                    remaining_time = deadline - time.monotonic()
                    if remaining_time <= 0:
                        raise Unavailable("native_deadline_exceeded")
                    for key, _ in poller.select(remaining_time):
                        block = os.read(key.fileobj.fileno(), min(65536, allowance - consumed + 1))
                        if not block:
                            poller.unregister(key.fileobj)
                            continue
                        consumed += len(block)
                        self.remaining -= len(block)
                        if consumed > allowance:
                            raise Unavailable("native_budget_exceeded")
                        if key.data:
                            output.extend(block)
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                raise Unavailable("native_deadline_exceeded")
            try:
                status = child.wait(timeout=remaining_time)
            except subprocess.TimeoutExpired:
                raise Unavailable("native_deadline_exceeded") from None
            if status != 0:
                raise Unavailable("native_read_failed")
            return bytes(output)
        finally:
            if child.poll() is None:
                child.kill()
            child.wait()
            child.stdout.close()
            child.stderr.close()


def inputs(selection, limits):
    """Accept only the agreed selection and whole-result limits."""
    if not isinstance(limits, dict) or set(limits) != {"max_containers", "max_result_bytes"}:
        raise ValueError("discovery_limits_invalid")
    for key, ceiling in (("max_containers", 32), ("max_result_bytes", 262144)):
        if type(limits[key]) is not int or not 1 <= limits[key] <= ceiling:
            raise ValueError("discovery_limits_invalid")
    if not isinstance(selection, dict):
        raise ValueError("discovery_selection_invalid")
    if selection == {"kind": "all_running"}:
        return None
    ids = selection.get("container_ids")
    if (set(selection) != {"kind", "container_ids"} or selection["kind"] != "containers"
            or not isinstance(ids, list) or not 1 <= len(ids) <= 32
            or any(not isinstance(value, str) or not CONTAINER_ID.fullmatch(value) for value in ids)
            or len(set(ids)) != len(ids)):
        raise ValueError("discovery_selection_invalid")
    return list(ids)


def text(value):
    """Unknown native text remains null."""
    return value if isinstance(value, str) else None


def strings(value):
    """Preserve ordered strings, empty values and unknown arrays distinctly."""
    return list(value) if isinstance(value, list) and all(isinstance(x, str) for x in value) else None


def timestamp(value):
    """Do not manufacture a timestamp for missing or malformed native data."""
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return value if parsed.tzinfo is not None else None
    except ValueError:
        return None


def empty_container(identity, observation="unavailable", code="native_read_failed"):
    """Retain the exact selected identity without fabricated empty facts."""
    return {"id": identity, "observation": observation, "name": None, "created_at": None,
            "state": None, "image": None, "command": {"state": "unknown", "argv": None},
            "entrypoint": {"state": "unknown", "argv": None}, "environment_names": None,
            "ports": None, "mounts": None, "networks": None,
            "problems": [problem(code)]}


def inspect(reads, identity):
    """Inspect by full immutable ID only, without shell or name fallback."""
    try:
        value = json.loads(reads.read(["container", "inspect", identity]))
    except (ValueError, UnicodeError):
        raise Unavailable("native_data_invalid") from None
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise Unavailable("native_data_invalid")
    return value[0]


def project(raw, identity):
    """Whitelist facts; never copy native config, labels, Env values or errors."""
    item = empty_container(identity)
    item["problems"] = []

    def unsupported(fact):
        item["problems"].append(problem("unsupported_fact", fact=fact))

    config = raw.get("Config") if isinstance(raw.get("Config"), dict) else {}
    state = raw.get("State") if isinstance(raw.get("State"), dict) else {}
    host = raw.get("HostConfig") if isinstance(raw.get("HostConfig"), dict) else {}
    network = raw.get("NetworkSettings") if isinstance(raw.get("NetworkSettings"), dict) else {}
    item.update(observation="observed", name=text(raw.get("Name")),
                created_at=timestamp(raw.get("Created")), state=text(state.get("Status")))
    if any(item[key] is None for key in ("name", "created_at", "state")):
        unsupported("identity")
    for key, native in (("command", "Cmd"), ("entrypoint", "Entrypoint")):
        argv = strings(config.get(native))
        item[key] = {"state": "unknown" if argv is None else "observed", "argv": argv}
        if argv is None:
            unsupported(key)
    item["image"] = {"reference": text(config.get("Image")), "id": text(raw.get("Image")),
                     "repo_digests": None}
    if item["image"]["reference"] is None or item["image"]["id"] is None:
        unsupported("image")
    # Container inspect does not supply image RepoDigests; image inspect is a separate read.
    env = strings(config.get("Env"))
    if env is not None:
        names = [entry.partition("=")[0] for entry in env]
        if all(ENV_NAME.fullmatch(name) for name in names):
            item["environment_names"] = names
        else:
            unsupported("environment_names")
    else:
        unsupported("environment_names")
    declared = config.get("ExposedPorts")
    published = network.get("Ports")
    if isinstance(declared, dict) and isinstance(published, dict):
        item["ports"] = []
        for key in dict.fromkeys([*declared, *published]):
            match = re.fullmatch(r"([0-9]+)/([a-z0-9]+)", key)
            if match is None or not 1 <= int(match[1]) <= 65535:
                unsupported("ports")
                continue
            if match[2] not in ("tcp", "udp", "sctp"):
                unsupported("ports")
            bindings = published.get(key)
            publications = None
            if key in published and bindings is None:
                publications = []
            elif isinstance(bindings, list):
                publications = []
                for binding in bindings:
                    if (not isinstance(binding, dict) or not isinstance(binding.get("HostIp"), str)
                            or not isinstance(binding.get("HostPort"), str)
                            or not binding["HostPort"].isdigit()
                            or not 1 <= int(binding["HostPort"]) <= 65535):
                        publications = None
                        unsupported("ports")
                        break
                    publications.append({"host_ip": binding["HostIp"], "host_port": int(binding["HostPort"])})
            else:
                unsupported("ports")
            item["ports"].append({"container_port": int(match[1]), "protocol": match[2],
                                  "declared": key in declared, "publications": publications})
    else:
        unsupported("ports")
    mounts = raw.get("Mounts")
    if isinstance(mounts, list):
        item["mounts"] = []
        for mount in mounts:
            if not isinstance(mount, dict):
                unsupported("mounts")
                continue
            kind = text(mount.get("Type"))
            target = text(mount.get("Destination"))
            source = None
            if kind in ("volume", "bind"):
                source = text(mount.get("Name" if kind == "volume" else "Source")) or None
                if source is None:
                    unsupported("mount_source")
            value = {"type": kind, "source": source, "target": target,
                     "read_only": not mount["RW"] if type(mount.get("RW")) is bool else None,
                     "tmpfs_size_bytes": None, "tmpfs_mode": None}
            # Tmpfs option strings are not parsed into invented native facts.
            if kind not in ("bind", "volume", "tmpfs") or target is None or value["read_only"] is None:
                unsupported("mounts")
            if kind == "tmpfs" or (kind == "bind" and mount.get("Propagation") not in (None, "rprivate")):
                unsupported("mount_options")
            item["mounts"].append(value)
    else:
        unsupported("mounts")
    networks = network.get("Networks")
    if isinstance(networks, dict):
        item["networks"] = []
        for name, value in networks.items():
            if not isinstance(value, dict):
                unsupported("networks")
                continue
            item["networks"].append({"id": text(value.get("NetworkID")), "name": name,
                                     "aliases": strings(value.get("Aliases"))})
            if item["networks"][-1]["id"] is None or item["networks"][-1]["aliases"] is None:
                unsupported("networks")
    else:
        unsupported("networks")
    if host.get("Privileged") is not False or host.get("NetworkMode") in ("host", "none"):
        unsupported("runtime_options")
    if any(host.get(key) for key in (
        "CapAdd", "CapDrop", "Devices", "DeviceRequests", "SecurityOpt", "Sysctls",
        "ExtraHosts", "Links", "VolumesFrom", "PidMode", "IpcMode", "UTSMode",
    )):
        unsupported("runtime_options")
    if any(config.get(key) for key in ("User", "WorkingDir", "StopSignal", "StopTimeout")):
        unsupported("unprojected_configuration")
    if config.get("Healthcheck") is not None or config.get("Labels"):
        unsupported("unprojected_configuration")
    return item


def observe(selection, limits, reads=None, endpoint_available=None):
    """Return bounded ordinary facts, never a partial successful selected set."""
    selected = inputs(selection, limits)
    result = {"format_version": 1, "selection": {"kind": selection["kind"], "container_ids": selected},
              "started_at": utc_now(), "observed_at": None, "complete": False,
              "containers": [], "problems": []}
    reads = reads or NativeReads()
    if endpoint_available is None:
        try:
            endpoint_available = bool(shutil.which("docker")) and stat.S_ISSOCK(os.stat(SOCKET).st_mode)
        except OSError:
            endpoint_available = False
    try:
        if not endpoint_available:
            raise Unavailable("local_docker_unavailable")
        if selected is None:
            try:
                listed = reads.read(["container", "ls", "--no-trunc", "--quiet"]).decode("ascii").splitlines()
            except UnicodeError:
                raise Unavailable("native_data_invalid") from None
            if (len(listed) > limits["max_containers"] or len(set(listed)) != len(listed)
                    or any(not CONTAINER_ID.fullmatch(value) for value in listed)):
                raise Unavailable("selection_not_captured")
            selected = listed
            result["selection"]["container_ids"] = selected
        if len(selected) > limits["max_containers"]:
            raise Unavailable("selection_limit_exceeded")
        for identity in selected:
            try:
                raw = inspect(reads, identity)
                created = timestamp(raw.get("Created"))
                if raw.get("Id") != identity or created is None:
                    raise Unavailable("identity_unverified")
                item = project(raw, identity)
                image_id = item["image"]["id"]
                if image_id is not None and re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
                    try:
                        image = json.loads(reads.read(["image", "inspect", image_id]))
                        if (not isinstance(image, list) or len(image) != 1 or not isinstance(image[0], dict)
                                or image[0].get("Id") != image_id):
                            raise ValueError
                        item["image"]["repo_digests"] = strings(image[0].get("RepoDigests"))
                        if item["image"]["repo_digests"] is None:
                            raise ValueError
                    except (ValueError, UnicodeError, Unavailable):
                        item["problems"].append(problem("image_unavailable", fact="image"))
                else:
                    item["problems"].append(problem("image_unavailable", fact="image"))
                fresh = inspect(reads, identity)
                if fresh.get("Id") != identity or fresh.get("Created") != raw.get("Created"):
                    item = empty_container(identity, "changed", "identity_changed")
                result["containers"].append(item)
            except Unavailable as error:
                result["containers"].append(empty_container(identity, code=str(error)))
        result["complete"] = all(item["observation"] == "observed" and not item["problems"]
                                 for item in result["containers"])
    except Unavailable as error:
        result["problems"].append(problem(str(error)))
        if selected is not None:
            result["containers"] = [empty_container(identity, code=str(error)) for identity in selected]
    result["observed_at"] = utc_now()
    encoded = json.dumps(result, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) <= limits["max_result_bytes"]:
        return encoded
    result["complete"] = False
    result["problems"] = [problem("result_budget_exceeded")]
    result["containers"] = [empty_container(identity, code="result_budget_exceeded")
                            for identity in selected or []]
    encoded = json.dumps(result, separators=(",", ":")).encode("utf-8")
    if len(encoded) > limits["max_result_bytes"]:
        raise Unavailable("result_budget_exceeded")
    return encoded


def main():
    """Only the projected JSON reaches stdout; diagnostics never echo inputs."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--selection", required=True)
    parser.add_argument("--limits", required=True)
    args = parser.parse_args()
    try:
        value = observe(json.loads(args.selection), json.loads(args.limits))
    except (ValueError, Unavailable, OSError):
        return 1
    sys.stdout.buffer.write(value)
    return 0


if __name__ == "__main__":
    sys.exit(main())
