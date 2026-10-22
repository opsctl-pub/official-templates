#!/usr/bin/env python3
"""Read inbound TCP connections for one exact Docker incarnation.

Ansible supplies the full ID and host PID from docker_container_info. This helper
does not wait, invoke Docker, change a namespace, or remove a runtime. It refuses
unobservable attribution rather than reporting zero connections.
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path


MAX_PROC_BYTES = 4 * 1024 * 1024
ACTIVE_TCP_STATES = {"01", "02", "03", "04", "05", "08", "09", "0B", "0C"}


def read_bounded(path: Path) -> str:
    """Bound kernel-table reads and refuse partial or malformed UTF-8 data."""
    with path.open("rb") as stream:
        data = stream.read(MAX_PROC_BYTES + 1)
    if len(data) > MAX_PROC_BYTES:
        raise ValueError("kernel table exceeds observation budget")
    return data.decode("ascii")


def process_identity(pid: int, container_id: str) -> tuple[str, int]:
    """Check Docker cgroup attribution and detect PID/namespace replacement."""
    root = Path("/proc") / str(pid)
    namespace = (root / "ns" / "net").stat().st_ino
    if namespace == Path("/proc/1/ns/net").stat().st_ino:
        raise ValueError("host network cannot identify isolated inbound connections")
    cgroups = read_bounded(root / "cgroup")
    if re.search(r"(?<![0-9a-f])" + re.escape(container_id) + r"(?![0-9a-f])", cgroups) is None:
        raise ValueError("process does not identify the admitted container")
    stat = read_bounded(root / "stat")
    fields = stat[stat.rindex(")") + 2:].split()
    if len(fields) < 20:
        raise ValueError("process identity is incomplete")
    return fields[19], namespace


def count_connections(pid: int, port: int) -> int:
    """Count active inbound sockets without treating TIME_WAIT as a client."""
    count = 0
    for name in ("tcp", "tcp6"):
        path = Path("/proc") / str(pid) / "net" / name
        text = read_bounded(path)
        lines = text.splitlines()
        if not lines or "local_address" not in lines[0]:
            raise ValueError("connection table header is unavailable")
        for line in lines[1:]:
            fields = line.split()
            if len(fields) < 10:
                raise ValueError("connection table row is incomplete")
            local_address, state = fields[1], fields[3]
            if re.fullmatch(r"[0-9A-Fa-f]+:[0-9A-Fa-f]{4}", local_address) is None:
                raise ValueError("connection address is malformed")
            if state not in ACTIVE_TCP_STATES | {"06", "07", "0A"}:
                raise ValueError("connection state is unknown")
            if int(local_address.rsplit(":", 1)[1], 16) == port and state in ACTIVE_TCP_STATES:
                count += 1
    return count


def observe(pid: int, container_id: str, port: int) -> dict:
    """Return one observation; a positive count is not a timeout declaration."""
    identity = process_identity(pid, container_id)
    count = count_connections(pid, port)
    if identity != process_identity(pid, container_id):
        raise ValueError("runtime identity changed while observing")
    return {
        "container_id": container_id,
        "active_inbound_connections": count,
        "observed_at": datetime.now(timezone.utc).isoformat(
            timespec="microseconds",
        ).replace("+00:00", "Z"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid", type=int, required=True)
    parser.add_argument("--container-id", required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    try:
        if (
            args.pid <= 0 or not 1 <= args.port <= 65535
            or re.fullmatch(r"[0-9a-f]{64}", args.container_id) is None
        ):
            raise ValueError("invalid identity")
        result = observe(args.pid, args.container_id, args.port)
    except (OSError, UnicodeError, ValueError):
        print(json.dumps({
            "container_id": None,
            "active_inbound_connections": None,
            "observed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }, separators=(",", ":")))
        return 1
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
