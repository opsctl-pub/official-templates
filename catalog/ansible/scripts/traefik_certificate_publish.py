#!/usr/bin/env python3
"""Validate/publish one staged native certificate pair and subject selection.

Template-local arguments: selection/store paths, subject/source/material/revision,
staged chain/key, requested hosts/trust and expected five-field snapshot file.
No issuance, Docker, scheduling, backend journal or cross-subject mutation occurs.
The prior native selection is restored on failed publication or bounded SNI probe.
"""

import argparse
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time

from certificate_facts import (
    HEADER, MAX_OUTPUT, canonical_uuid, empty, hosts_list, pair, probe, read_file,
    selection, snapshot, subject_key,
)


def sync_directory(path):
    """Persist native name publication before claiming success."""
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write(path, data, mode=0o600):
    """Publish a complete file without exposing a partial chain or selection."""
    path = Path(path)
    if path.parent.resolve() != path.parent or path.is_symlink():
        raise ValueError("unsafe publication path")
    descriptor, temporary = tempfile.mkstemp(prefix=".certificate-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def publish(args):
    """Keep compare, native name activation and restoration under one lock."""
    root = Path(args.root)
    path = Path(args.selection)
    for directory in (root, path.parent):
        if not directory.is_absolute() or directory.resolve() != directory or not directory.is_dir():
            raise ValueError("publication directory unavailable")
    expected = json.loads(read_file(args.expected_file, 8192, private=True))
    if set(expected) != set(snapshot(empty())) or expected["presence"] not in {"present", "absent"}:
        raise ValueError("invalid expected selection")
    hosts = hosts_list(args.hosts)
    key = subject_key(args.subject)
    if args.material:
        canonical_uuid(args.material)
    if args.revision:
        canonical_uuid(args.revision)
    if args.source == "custom" and (not args.material or not args.revision):
        raise ValueError("custom identity missing")
    if args.source == "native" and not args.revision:
        raise ValueError("native revision missing")
    if args.remove and expected["presence"] == "present" and expected["source"] != args.source:
        raise ValueError("selected source changed")
    if not ipaddress.ip_address(args.address).is_loopback or not 1 <= args.port <= 65535:
        raise ValueError("invalid local listener")
    trust = read_file(args.trust_file).decode("ascii") if args.trust_file else None
    staged = None
    desired = None
    if not args.remove:
        if not hosts:
            raise ValueError("hosts missing")
        chain = read_file(args.chain)
        private = read_file(args.key, private=True)
        _, fingerprint = pair(chain, private, hosts, args.fingerprint)
        staged = None if args.source == 'native' else Path(tempfile.mkdtemp(prefix=".pair-" + key + "-", dir=root))
        try:
            if staged is None:
                final = Path(args.key).parent
                if not final.is_relative_to(root) or Path(args.chain) != final / 'tls.crt' or Path(args.key) != final / 'tls.key':
                    raise ValueError('native immutable pair required')
            else:
                atomic_write(staged / "tls.crt", chain)
                atomic_write(staged / "tls.key", private)
                sync_directory(staged)
                final = root / staged.name.removeprefix(".")
                os.rename(staged, final)
                staged = final
                sync_directory(root)
            metadata = {"subject": args.subject, "source": args.source,
                        "material_id": args.material, "revision_id": args.revision, "hosts": hosts}
            document = {"tls": {"certificates": [{"certFile": str(final / "tls.crt"),
                                                  "keyFile": str(final / "tls.key")}]}}
            desired = (HEADER + json.dumps(metadata, separators=(",", ":")) + "\n"
                       + json.dumps(document, separators=(",", ":")) + "\n").encode()
        except BaseException:
            if staged is not None:
                shutil.rmtree(staged)
            raise
    published = False
    restored = True
    completed = False
    phase = "apply"
    failure_code = "certificate_state_changed"
    try:
        descriptor = os.open(root / ".selection.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "rb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            before, prior = selection(path, root, args.subject)
            if snapshot(before) != expected:
                raise ValueError("selection changed")
            try:
                if args.remove:
                    if prior is not None:
                        path.unlink()
                        published = True
                        sync_directory(path.parent)
                else:
                    # Mark before rename: a durability failure may follow publication.
                    published = True
                    atomic_write(path, desired, 0o644)
                    phase = "probe"
                    failure_code = "certificate_serving_unverified"
                    deadline = time.monotonic() + 25
                    for host in hosts:
                        while True:
                            actual = probe(host, fingerprint, trust, args.address, args.port, deadline)
                            if actual["served"] == "matched" and actual["trusted"] is True:
                                break
                            if time.monotonic() >= deadline:
                                raise ValueError("serving unverified")
                            time.sleep(min(0.2, max(0, deadline - time.monotonic())))
                result, _ = selection(path, root, args.subject)
                completed = True
                return {"certificate_observation": result}, True
            except BaseException:
                if published:
                    try:
                        current = read_file(path, 64 * 1024) if path.exists() else None
                        if current != (None if args.remove else desired):
                            raise ValueError("selection changed during restoration")
                        if prior is None:
                            path.unlink(missing_ok=True)
                            sync_directory(path.parent)
                        else:
                            atomic_write(path, prior, 0o644)
                    except (OSError, ValueError):
                        restored = False
                raise
    except (OSError, ValueError, KeyError, TypeError):
        try:
            facts, _ = selection(path, root, args.subject)
        except Exception:
            facts = empty()
        facts["outcome"] = "failed" if restored else "incomplete"
        return {"certificate_observation": facts,
                "procedure_error": {"phase": phase if restored else "restore",
                                    "code": failure_code if restored else "restoration_failed"}}, False
    finally:
        # Failed restoration may still select the new pair: retain it as liability.
        if staged is not None and (not published or (restored and not completed)):
            shutil.rmtree(staged)


def main():
    """Emit one bounded safe result; exceptions never expose native paths/material."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--selection", required=True)
    parser.add_argument("--root", required=True)
    parser.add_argument("--subject", type=json.loads, required=True)
    parser.add_argument("--source", choices=("automatic", "custom", "native"), required=True)
    parser.add_argument("--material")
    parser.add_argument("--revision")
    parser.add_argument("--chain")
    parser.add_argument("--key")
    parser.add_argument("--hosts", type=json.loads, required=True)
    parser.add_argument("--fingerprint")
    parser.add_argument("--expected-file", required=True)
    parser.add_argument("--trust-file")
    parser.add_argument("--address", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--remove", action="store_true")
    args = parser.parse_args()
    try:
        result, success = publish(args)
    except Exception:
        result = {"certificate_observation": empty(),
                  "procedure_error": {"phase": "stage", "code": "certificate_material_invalid"}}
        success = False
    encoded = json.dumps(result, separators=(",", ":"))
    if len(encoded.encode()) > MAX_OUTPUT:
        encoded = json.dumps({"certificate_observation": empty(),
                              "procedure_error": {"phase": "observe", "code": "certificate_serving_unverified"}})
        success = False
    print(encoded)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
