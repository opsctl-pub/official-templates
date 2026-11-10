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
from datetime import datetime, timezone


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

    def read(self, arguments, limit, *, combined=False):
        """Return complete successful output within one aggregate byte/time bound."""
        if time.monotonic() >= self.deadline:
            raise Unavailable()
        child = subprocess.Popen(
            [*self.command, *arguments], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT if combined else subprocess.PIPE,
            env=self.environment,
        )
        streams = [bytearray(), bytearray()]
        consumed = 0
        try:
            with selectors.DefaultSelector() as poller:
                poller.register(child.stdout, selectors.EVENT_READ, 0)
                if child.stderr is not None:
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
                    if child.stderr is not None:
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


def safe_tail(streams, *, max_lines=50):
    """Omit whole tails containing unsafe text; never edit a protected literal."""
    for stream in streams:
        validation = SGR.sub("", stream)
        if (any(marker in stream or marker in validation for marker in MARKERS)
                or any(unicodedata.category(char).startswith("C")
                       and char not in "\n\r\t\u200c\u200d" for char in validation)):
            raise Unavailable()
    if sum(len(stream.splitlines()) for stream in streams) > max_lines:
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


def log_inputs(raw):
    """Accept only the ordinary action's closed selectors and bounded line request."""
    if (not isinstance(raw, dict)
            or set(raw) != {"container_name", "container_id", "group", "lines", "operational_path"}
            or not isinstance(raw["operational_path"], str)
            or not 0 < len(raw["operational_path"]) <= 4096 or "\x00" in raw["operational_path"]
            or type(raw["lines"]) is not int or not 1 <= raw["lines"] <= 1000):
        raise Unavailable()
    name, identity, group = raw["container_name"], raw["container_id"], raw["group"]
    if (name is not None and (not isinstance(name, str) or not SERVICE.fullmatch(name))
            or identity is not None and (not isinstance(identity, str) or not CONTAINER_ID.fullmatch(identity))
            or name is not None and identity is not None
            or name is None and identity is None and group is None):
        raise Unavailable()
    labels = {}
    if group is not None:
        if not isinstance(group, dict):
            raise Unavailable()
        if group.get("kind") == "image":
            if (set(group) != {"kind", "organization_id", "deployment_id"}
                    or any(not isinstance(group[key], str) or not UUID.fullmatch(group[key])
                           for key in ("organization_id", "deployment_id"))):
                raise Unavailable()
            labels = {"com.opsctl.managed": "true", "com.opsctl.org_id": group["organization_id"],
                      "com.opsctl.deployment_id": group["deployment_id"]}
        elif group.get("kind") == "compose":
            if (set(group) != {"kind", "project_name", "working_directory"}
                    or not isinstance(group["project_name"], str) or len(group["project_name"]) > 128
                    or not PROJECT.fullmatch(group["project_name"])
                    or not isinstance(group["working_directory"], str)
                    or not 0 < len(group["working_directory"]) <= 4096
                    or not os.path.isabs(group["working_directory"])
                    or os.path.normpath(group["working_directory"]) != group["working_directory"]):
                raise Unavailable()
            safe_tail((group["working_directory"],))
            labels = {"com.docker.compose.project": group["project_name"],
                      "com.docker.compose.project.working_dir": group["working_directory"]}
        else:
            raise Unavailable()
    return labels


def log_identity(reads, selector, labels):
    """Inspect only identity, exact name and the read group's required labels."""
    fields = ['"id":{{json .Id}}', '"name":{{json .Name}}']
    for index, key in enumerate(labels):
        fields.append('"label' + str(index) + '":{{json (index .Config.Labels "' + key + '")}}')
    output, error = reads.read([
        "container", "inspect", "--format", "{" + ",".join(fields) + "}", selector,
    ], 16384)
    observed = json.loads(output)
    if (error or not isinstance(observed, dict)
            or not isinstance(observed.get("id"), str) or not CONTAINER_ID.fullmatch(observed["id"])
            or not isinstance(observed.get("name"), str) or not observed["name"].startswith("/")):
        raise Unavailable()
    name = observed["name"][1:]
    if (not SERVICE.fullmatch(name)
            or any(observed.get("label" + str(index)) != value for index, value in enumerate(labels.values()))):
        raise Unavailable()
    return {"id": observed["id"], "name": name}


def log_selection(reads, request, labels):
    """Resolve once; never choose a replica or use a replacement name after selection."""
    selector = request["container_id"] or request["container_name"]
    if selector is not None:
        member = log_identity(reads, selector, labels)
        if (request["container_id"] is not None and member["id"] != request["container_id"]
                or request["container_name"] is not None and member["name"] != request["container_name"]):
            raise Unavailable()
        return [member]
    arguments = ["container", "ls", "--all", "--no-trunc"]
    for key, value in labels.items():
        arguments.extend(["--filter", "label=" + key + "=" + value])
    output, error = reads.read([*arguments, "--format", "{{.ID}}"], 16384)
    identities = output.splitlines()
    if (error or not identities or len(identities) > 128 or len(set(identities)) != len(identities)
            or any(not CONTAINER_ID.fullmatch(value) for value in identities)):
        raise Unavailable()
    members = []
    for identity in identities:
        member = log_identity(reads, identity, labels)
        if member["id"] != identity:
            raise Unavailable()
        members.append(member)
    return members


def ordinary_tail(reads, member, lines):
    """Keep Docker record order in one pipe and shrink only complete recent tails."""
    tail = lines
    while True:
        try:
            output, _ = reads.read([
                "logs", "--timestamps", "--tail", str(tail), member["id"],
            ], 16384, combined=True)
            safe_tail((output,), max_lines=tail)
            return {"logs": output, "line_count": len(output.splitlines()), "limited": tail < lines}
        except Overflow:
            if tail == 1:
                raise Unavailable() from None
            tail = max(1, tail // 2)


def ordinary_read(raw, deadline):
    """Publish no partial content, native errors or guessed membership."""
    result = {"status": "unavailable", "observed_at": datetime.now(timezone.utc).isoformat()}
    try:
        labels = log_inputs(raw)
        executable = shutil.which("docker", path=raw["operational_path"])
        if executable is None:
            raise Unavailable()
        docker = os.path.realpath(executable)
        with tempfile.TemporaryDirectory(prefix="docker-logs-", dir=os.path.dirname(os.path.abspath(__file__))) as config:
            reads = NativeReads(docker, config, deadline)
            members = log_selection(reads, raw, labels)
            if len(members) > 1:
                result.update(status="selection_required", names=[member["name"] for member in members[:20]],
                              names_limited=len(members) > 20)
            else:
                member = members[0]
                content = ordinary_tail(reads, member, raw["lines"])
                result.update(status="available", container_id=member["id"], container_name=member["name"], **content)
    except (Unavailable, OSError, ValueError, subprocess.SubprocessError):
        pass
    result["observed_at"] = datetime.now(timezone.utc).isoformat()
    return result


def main():
    """Emit private diagnostic JSON only; collection never replaces native failure."""
    deadline = time.monotonic() + 10
    if len(sys.argv) == 4 and sys.argv[1:3] == ["--mode", "logs"]:
        result = {"status": "unavailable", "observed_at": datetime.now(timezone.utc).isoformat()}
        try:
            if len(sys.argv[3].encode("utf-8")) > 32768:
                raise Unavailable()
            result = ordinary_read(json.loads(sys.argv[3]), deadline)
        except (Unavailable, ValueError, UnicodeError):
            pass
        sys.stdout.write(json.dumps(result, ensure_ascii=True) + "\n")
        return
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
