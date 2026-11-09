"""Collect bounded whole application log tails from qualified immutable container IDs."""
import json
import os
import re
import selectors
import shutil
import subprocess
import sys
import tempfile
import time
import unicodedata


CONTAINER_ID = re.compile(r"[0-9a-f]{64}\Z")
SERVICE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,254}\Z")
PROJECT = re.compile(r"[a-z0-9][a-z0-9_-]{0,254}\Z")
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z")
IMAGE_LABELS = {"com.opsctl.managed", "com.opsctl.org_id", "com.opsctl.deployment_id",
                "com.opsctl.app", "com.opsctl.project_id"}
OPTIONAL_LABELS = {"com.opsctl.revision_id", "com.opsctl.secret_files"}
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


def image_inputs(raw):
    """Require explicit image identity and only the supported managed label scope."""
    if (not isinstance(raw, dict)
            or set(raw) != {"container_name", "previous_ids", "labels", "operational_path"}
            or not isinstance(raw["operational_path"], str)
            or not 0 < len(raw["operational_path"]) <= 4096 or "\x00" in raw["operational_path"]
            or not isinstance(raw["container_name"], str)
            or not SERVICE.fullmatch(raw["container_name"])
            or not isinstance(raw["previous_ids"], list) or len(raw["previous_ids"]) > 4
            or any(not isinstance(value, str) or not CONTAINER_ID.fullmatch(value)
                   for value in raw["previous_ids"])
            or len(set(raw["previous_ids"])) != len(raw["previous_ids"])
            or not isinstance(raw["labels"], dict)):
        raise Unavailable()
    labels = raw["labels"]
    if (not IMAGE_LABELS <= labels.keys() <= IMAGE_LABELS | OPTIONAL_LABELS
            or labels["com.opsctl.managed"] != "true"
            or not isinstance(labels["com.opsctl.app"], str)
            or not SERVICE.fullmatch(labels["com.opsctl.app"])):
        raise Unavailable()
    for key in ("com.opsctl.org_id", "com.opsctl.deployment_id", "com.opsctl.project_id",
                "com.opsctl.revision_id", "com.opsctl.secret_files"):
        if key not in labels or (key == "com.opsctl.project_id" and labels[key] == ""):
            continue
        if not isinstance(labels[key], str) or not UUID.fullmatch(labels[key]):
            raise Unavailable()
    return raw


def image_member(reads, request):
    """Discover once by name, then qualify and retain restricted state by full ID."""
    output, error = reads.read([
        "container", "inspect", "--format", "{{json .Id}}", request["container_name"],
    ], 65536)
    identity = json.loads(output)
    if (error or not isinstance(identity, str) or not CONTAINER_ID.fullmatch(identity)
            or identity in request["previous_ids"]):
        raise Unavailable()
    output, error = reads.read([
        "container", "inspect", "--format",
        '{"id":{{json .Id}},"labels":{{json .Config.Labels}},'
        '"status":{{json .State.Status}},"running":{{json .State.Running}},'
        '"exit_code":{{json .State.ExitCode}},"oom_killed":{{json .State.OOMKilled}},'
        '"restart_count":{{json .RestartCount}},"error":{{json .State.Error}},'
        '"health":{{with index .State "Health"}}{{json .Status}}{{else}}"none"{{end}}}',
        identity,
    ], 65536)
    observed = json.loads(output)
    if (error or not isinstance(observed, dict) or observed.get("id") != identity
            or not isinstance(observed.get("labels"), dict)
            or {key: value for key, value in observed["labels"].items()
                if key in IMAGE_LABELS | OPTIONAL_LABELS} != request["labels"]):
        raise Unavailable()
    state = {key: observed.get(key) for key in
             ("status", "running", "exit_code", "oom_killed", "restart_count", "health")}
    if (state["status"] not in ("created", "running", "paused", "restarting", "removing", "exited", "dead")
            or state["health"] not in ("none", "starting", "healthy", "unhealthy")
            or type(state["running"]) is not bool or type(state["oom_killed"]) is not bool
            or type(state["exit_code"]) is not int or type(state["restart_count"]) is not int
            or state["restart_count"] < 0):
        raise Unavailable()
    native_error = observed.get("error")
    if isinstance(native_error, str):
        try:
            if len(native_error.encode("utf-8")) <= 4096:
                safe_tail((native_error,))
                state["error"] = native_error
        except (Unavailable, UnicodeError):
            pass
    return {"id": identity, "state": state}


def collect_logs(reads, member):
    """Shrink only whole tails inside the original aggregate deadline."""
    for tail in (50, 20, 10):
        try:
            stdout, stderr = safe_tail(reads.read(["logs", "--tail", str(tail), member["id"]], 16384))
            return {**member, "status": "available", "stdout": stdout, "stderr": stderr}
        except Overflow:
            continue
    return {**member, "status": "unavailable"}


def collect_member(reads, request, member):
    """Keep real stdout and stderr only after exact scope and complete tail checks."""
    unavailable = {**member, "status": "unavailable"}
    try:
        scoped(reads, request, member)
        return collect_logs(reads, member)
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
        raw = json.loads(sys.argv[1])
        image = isinstance(raw, dict) and "container_name" in raw
        request = image_inputs(raw) if image else inputs(raw)
        if image:
            executable = shutil.which("docker", path=request["operational_path"])
            if executable is None:
                raise Unavailable()
            docker = os.path.realpath(executable)
        else:
            docker = request["docker"]
        with tempfile.TemporaryDirectory(prefix="docker-logs-", dir=os.path.dirname(os.path.abspath(__file__))) as config:
            reads = NativeReads(docker, config, deadline)
            if image:
                member = image_member(reads, request)
                try:
                    members = [collect_logs(reads, member)]
                except (Unavailable, OSError, ValueError, subprocess.SubprocessError):
                    members = [{**member, "status": "unavailable"}]
            else:
                members = [collect_member(reads, request, member) for member in request["members"]]
        result = {"status": "observed", "members": members, "omitted": 0 if image else request["omitted"]}
    except Exception:
        pass
    sys.stdout.write(json.dumps(result, ensure_ascii=True) + "\n")


if __name__ == "__main__":
    main()
