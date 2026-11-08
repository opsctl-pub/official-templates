"""Collect bounded whole application log tails from exact observed Compose members."""
import json
import os
import re
import selectors
import subprocess
import sys
import tempfile
import time
import unicodedata


CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")
SERVICE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}\Z")
PROJECT = re.compile(r"[a-z0-9][a-z0-9_-]{0,254}\Z")
MARKERS = ("OPERATION_STEP=", "TEMPLATE_OUTPUT_JSON=", "TF_OUTPUT_JSON=", "TF_DESTROY_JSON=")
SGR = re.compile(r"\x1b\[[0-9;:]{0,64}m")


class Unavailable(Exception):
    """Native content cannot safely be published."""


class Overflow(Unavailable):
    """A whole smaller tail may still fit the same observation deadline."""


class NativeReads:
    """Count both pipes and reap only this collector's literal-argv CLI children."""

    def __init__(self, docker, config, deadline):
        self.command = [docker, "--config", config, "--host", "unix:///var/run/docker.sock"]
        self.environment = {key: value for key, value in os.environ.items()
                            if not key.startswith("DOCKER_")}
        self.deadline = deadline

    def read(self, arguments, limit):
        """Return complete successful output within one aggregate byte/time bound."""
        if time.monotonic() >= self.deadline:
            raise Unavailable()
        child = subprocess.Popen(
            [*self.command, *arguments], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.environment,
        )
        streams = [bytearray(), bytearray()]
        consumed = 0
        try:
            with selectors.DefaultSelector() as poller:
                poller.register(child.stdout, selectors.EVENT_READ, 0)
                poller.register(child.stderr, selectors.EVENT_READ, 1)
                while poller.get_map():
                    remaining = self.deadline - time.monotonic()
                    if remaining <= 0:
                        raise Unavailable()
                    for key, _ in poller.select(remaining):
                        block = os.read(key.fileobj.fileno(), min(65536, limit - consumed + 1))
                        if not block:
                            poller.unregister(key.fileobj)
                            continue
                        consumed += len(block)
                        if consumed > limit:
                            raise Overflow()
                        streams[key.data].extend(block)
            remaining = self.deadline - time.monotonic()
            if remaining <= 0 or child.wait(timeout=remaining) != 0:
                raise Unavailable()
            return tuple(bytes(stream).decode("utf-8", errors="strict") for stream in streams)
        finally:
            try:
                if child.poll() is None:
                    child.kill()
            finally:
                try:
                    child.wait()
                finally:
                    child.stdout.close()
                    child.stderr.close()


def inputs(raw):
    """Accept only bounded observed identities and already normalized native scope."""
    if (not isinstance(raw, dict)
            or set(raw) != {"docker", "project", "workspace", "members", "omitted"}):
        raise Unavailable()
    docker, project, workspace = raw["docker"], raw["project"], raw["workspace"]
    if (not isinstance(docker, str) or len(docker) > 4096 or not os.path.isabs(docker)
            or os.path.normpath(docker) != docker or os.path.islink(docker)
            or not os.path.isfile(docker) or not os.access(docker, os.X_OK)
            or not isinstance(project, str) or not PROJECT.fullmatch(project)
            or not isinstance(workspace, str) or len(workspace) > 4096
            or not os.path.isabs(workspace) or os.path.normpath(workspace) != workspace
            or not isinstance(raw["members"], list) or len(raw["members"]) > 4
            or type(raw["omitted"]) is not int or not 0 <= raw["omitted"] <= 128):
        raise Unavailable()
    seen = set()
    for member in raw["members"]:
        if (not isinstance(member, dict) or set(member) != {"id", "service"}
                or not isinstance(member["id"], str) or not CONTAINER_ID.fullmatch(member["id"])
                or member["id"] in seen or not isinstance(member["service"], str)
                or not SERVICE.fullmatch(member["service"])):
            raise Unavailable()
        seen.add(member["id"])
    return raw


def scoped(reads, request, member):
    """Read labels only, never container configuration or name-based fallbacks."""
    output, error = reads.read([
        "container", "inspect", "--format", "{{json .Config.Labels}}", member["id"],
    ], 65536)
    labels = json.loads(output)
    if (error or not isinstance(labels, dict)
            or labels.get("com.docker.compose.project") != request["project"]
            or labels.get("com.docker.compose.service") != member["service"]
            or labels.get("com.docker.compose.project.working_dir") != request["workspace"]):
        raise Unavailable()


def safe_tail(streams):
    """Omit whole tails containing unsafe text; never edit a protected literal."""
    for stream in streams:
        validation = SGR.sub("", stream)
        if (any(marker in stream or marker in validation for marker in MARKERS)
                or any(unicodedata.category(char).startswith("C")
                       and char not in "\n\r\t\u200c\u200d" for char in validation)):
            raise Unavailable()
    if sum(len(stream.splitlines()) for stream in streams) > 50:
        raise Overflow()
    return streams


def collect_member(reads, request, member):
    """Keep real stdout and stderr only after exact scope and complete tail checks."""
    unavailable = {**member, "status": "unavailable"}
    try:
        scoped(reads, request, member)
        for tail in (50, 20, 10):
            try:
                stdout, stderr = safe_tail(reads.read(["logs", "--tail", str(tail), member["id"]], 16384))
                return {**member, "status": "available", "stdout": stdout, "stderr": stderr}
            except Overflow:
                continue
    except (Unavailable, OSError, ValueError, subprocess.SubprocessError):
        pass
    return unavailable


def main():
    """Emit private diagnostic JSON only; collection never replaces native failure."""
    deadline = time.monotonic() + 10
    result = {"status": "unavailable", "members": [], "omitted": 0}
    try:
        if len(sys.argv) != 2 or len(sys.argv[1].encode("utf-8")) > 32768:
            raise Unavailable()
        request = inputs(json.loads(sys.argv[1]))
        with tempfile.TemporaryDirectory(prefix="docker-logs-", dir=os.path.dirname(os.path.abspath(__file__))) as config:
            reads = NativeReads(request["docker"], config, deadline)
            members = [collect_member(reads, request, member) for member in request["members"]]
        result = {"status": "observed", "members": members, "omitted": request["omitted"]}
    except Exception:
        pass
    sys.stdout.write(json.dumps(result, ensure_ascii=True) + "\n")


if __name__ == "__main__":
    main()
