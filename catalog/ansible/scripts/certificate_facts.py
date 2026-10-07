#!/usr/bin/env python3
"""Read native selection, leaf/SNI, enrollment or CSR facts without mutation.

Arguments are template-local paths, never backend-selected remote paths. Selection
metadata lives in a YAML comment; it is not an API receipt or a compatibility
format. --snapshot emits only the five compare-before-publication fields.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import subprocess
import sys
import time
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
import yaml


MAX_OUTPUT = 128 * 1024
MAX_MATERIAL = 256 * 1024
HEADER = "# certificate "
SNAPSHOT_FIELDS = (
    "presence", "source", "material_id", "revision_id", "leaf_fingerprint_sha256",
)


def utc(value=None):
    """Return UTC facts without local timezone ambiguity."""
    return (value or datetime.now(timezone.utc)).astimezone(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def canonical_uuid(value):
    """Accept only the canonical spelling used in native subject filenames."""
    if not isinstance(value, str) or str(UUID(value)) != value:
        raise ValueError("invalid UUID")
    return value


def subject_key(value):
    """Keep Server and Deployment selections separate."""
    if set(value) != {"type", "id"} or value["type"] not in {"server", "deployment"}:
        raise ValueError("invalid subject")
    return value["type"] + "-" + canonical_uuid(value["id"])


def hosts_list(values):
    """Bound and validate canonical DNS names before native probing."""
    if not isinstance(values, list) or len(values) > 100:
        raise ValueError("invalid hosts")
    if any(not isinstance(host, str) for host in values) or values != sorted(set(values)):
        raise ValueError("invalid hosts")
    for host in values:
        if not re.fullmatch(
            r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
            r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*", host,
        ):
            raise ValueError("invalid hostname")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            continue
        raise ValueError("DNS required")
    return values


def read_file(path, maximum=MAX_MATERIAL, private=False):
    """Bound reads and reject linked or nonregular native material."""
    path = Path(path)
    if not path.is_absolute() or path.resolve() != path:
        raise ValueError("unsafe path")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
            raise ValueError("invalid file")
        if private and (before.st_uid != 0 or before.st_mode & 0o077):
            raise ValueError("private file required")
        value = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        if len(value) > maximum or any(getattr(before, field) != getattr(after, field) for field in (
            "st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns",
        )):
            raise ValueError("changed file")
        return value


def validity(leaf, name):
    """Support the installed cryptography versions without losing UTC."""
    value = getattr(leaf, name + "_utc", None)
    return value if value is not None else getattr(leaf, name).replace(tzinfo=timezone.utc)


def public_key(value):
    """Canonical public-key representation; never return private key bytes."""
    return value.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def covers(leaf, hosts):
    """Check DNS SAN coverage, including one-label wildcard semantics."""
    names = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    names = names.get_values_for_type(x509.DNSName)
    return all(any(
        host == name.lower() or (
            name.startswith("*.") and host.count(".") == name.count(".")
            and host.endswith(name[1:].lower())
        ) for name in names
    ) for host in hosts)


def pair(chain, key, hosts, expected=None, current=True):
    """Validate bounded native pair identity, validity and requested SANs."""
    leaf = x509.load_pem_x509_certificate(chain)
    private = serialization.load_pem_private_key(key, password=None)
    fingerprint = leaf.fingerprint(hashes.SHA256()).hex()
    now = datetime.now(timezone.utc)
    if (public_key(leaf.public_key()) != public_key(private.public_key())
            or not covers(leaf, hosts)
            or (expected is not None and fingerprint != expected)
            or (current and not validity(leaf, "not_valid_before") <= now < validity(leaf, "not_valid_after"))):
        raise ValueError("invalid material")
    return leaf, fingerprint


def empty(presence="unknown"):
    """Unavailable facts never become an absent selection."""
    return {
        "outcome": "incomplete" if presence == "unknown" else "succeeded",
        "observed_at": utc(), "presence": presence, "source": None,
        "material_id": None, "revision_id": None, "leaf_fingerprint_sha256": None,
        "not_before": None, "not_after": None, "selected_hosts": [],
        "binding_count": 0 if presence == "absent" else None,
        "hosts": [], "renewal": None,
    }


def snapshot(facts):
    """Compare material selection, not probe timestamps or scheduler timing."""
    return {field: facts[field] for field in SNAPSHOT_FIELDS}


def referenced(directory, material):
    """Bound native TLS-reference observation before one unused revision retires."""
    material = Path(material)
    directory = Path(directory)
    if not material.is_absolute() or material.resolve() != material or directory.resolve() != directory:
        raise ValueError("unsafe reference path")
    found = False
    visits = 0
    with os.scandir(directory) as entries:
        for index, entry in enumerate(entries):
            if index >= 128:
                raise ValueError("reference inventory exceeded")
            if entry.name.startswith('.') or not entry.name.endswith(('.yml', '.yaml', '.toml')):
                continue
            raw = read_file(entry.path, 64 * 1024)
            if entry.name.endswith('.toml'):
                import tomllib
                pending = [tomllib.loads(raw.decode())]
            else:
                pending = [yaml.safe_load(raw)]
            while pending:
                value = pending.pop()
                visits += 1
                if visits > 16384:
                    raise ValueError("native document exceeded")
                if isinstance(value, dict):
                    for key, child in value.items():
                        if key in {'certFile', 'keyFile'}:
                            if not isinstance(child, str) or not Path(child).is_absolute():
                                raise ValueError("native reference unavailable")
                            if Path(child).resolve().is_relative_to(material):
                                found = True
                        elif isinstance(child, (list, dict)):
                            pending.append(child)
                elif isinstance(value, list):
                    pending.extend(value)
    return found


def selection(path, root, subject):
    """Read one native Traefik TLS document and its actual selected pair."""
    try:
        raw = read_file(path, 64 * 1024)
    except FileNotFoundError:
        # Missing ancestors are not proof that the installed selection is absent.
        if Path(path).parent.resolve() != Path(path).parent or not Path(path).parent.is_dir():
            raise ValueError("selection directory unavailable") from None
        return empty("absent"), None
    header, separator, body = raw.decode("utf-8").partition("\n")
    if not separator or not header.startswith(HEADER):
        raise ValueError("unrecognized selection")
    metadata = json.loads(header[len(HEADER):])
    if set(metadata) != {"subject", "source", "material_id", "revision_id", "hosts"}:
        raise ValueError("invalid selection metadata")
    if metadata["subject"] != subject or metadata["source"] not in {"automatic", "custom", "native"}:
        raise ValueError("selection changed")
    hosts = hosts_list(metadata["hosts"])
    if not hosts:
        raise ValueError("selected hosts missing")
    for field in ("material_id", "revision_id"):
        if metadata[field] is not None:
            canonical_uuid(metadata[field])
    if (metadata["source"] == "custom" and any(metadata[field] is None for field in ("material_id", "revision_id"))
            or metadata["source"] == "native" and metadata["revision_id"] is None):
        raise ValueError("selected material identity missing")
    document = yaml.safe_load(body)
    if not isinstance(document, dict) or set(document) != {"tls"}:
        raise ValueError("invalid native selection")
    if set(document["tls"]) != {"certificates"} or len(document["tls"]["certificates"]) != 1:
        raise ValueError("invalid native selection")
    files = document["tls"]["certificates"][0]
    if set(files) != {"certFile", "keyFile"}:
        raise ValueError("invalid native pair")
    for value in files.values():
        if not Path(value).is_relative_to(Path(root)):
            raise ValueError("outside native certificate store")
    leaf, fingerprint = pair(
        read_file(files["certFile"]), read_file(files["keyFile"], private=True), hosts, current=False,
    )
    facts = empty("present")
    facts.update(
        source=metadata["source"], material_id=metadata["material_id"],
        revision_id=metadata["revision_id"], leaf_fingerprint_sha256=fingerprint,
        not_before=utc(validity(leaf, "not_valid_before")),
        not_after=utc(validity(leaf, "not_valid_after")), selected_hosts=hosts,
        binding_count=1,
    )
    if facts["source"] == "automatic":
        facts["renewal"] = dict.fromkeys(("enabled", "active", "next_due_at"))
        facts["outcome"] = "incomplete"
    return facts, raw


def selection_path_present(path):
    """Check the root-owned selection chain without following missing or linked ancestors."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError("unsafe selection path")
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in path.parts[1:-1]:
            try:
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=descriptor)
            except FileNotFoundError:
                return False
            os.close(descriptor)
            descriptor = child
            if os.fstat(descriptor).st_uid != 0:
                raise ValueError("foreign selection directory")
        try:
            entry = os.stat(path.name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return False
        if not stat.S_ISREG(entry.st_mode) or entry.st_uid != 0:
            raise ValueError("foreign selection file")
        return True
    finally:
        os.close(descriptor)


def selection_only(args):
    """Observe a stable selection without requiring a gateway or timer enrollment."""
    present = selection_path_present(args.selection)
    facts, raw = selection(args.selection, args.root, args.subject) if present else (empty("absent"), None)
    if selection_path_present(args.selection) != present:
        raise ValueError("selection changed during observation")
    after, after_raw = selection(args.selection, args.root, args.subject) if present else (empty("absent"), None)
    if after_raw != raw or snapshot(after) != snapshot(facts):
        raise ValueError("selection changed during observation")
    return snapshot(facts)


def probe(host, fingerprint, trust, address, port, deadline):
    """Read one loopback SNI leaf and separately establish selected trust."""
    result = {"hostname": host, "served": "unknown", "trusted": None,
              "leaf_fingerprint_sha256": None}
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return result
    try:
        context = ssl.create_default_context(cadata=trust)
        with socket.create_connection((address, port), timeout=min(2, remaining)) as connection:
            connection.settimeout(min(2, max(0.001, deadline - time.monotonic())))
            with context.wrap_socket(connection, server_hostname=host) as tls:
                leaf = tls.getpeercert(binary_form=True)
        trusted = True
    except ssl.SSLCertVerificationError:
        if deadline <= time.monotonic():
            return result
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((address, port), timeout=min(2, deadline - time.monotonic())) as connection:
                connection.settimeout(min(2, max(0.001, deadline - time.monotonic())))
                with context.wrap_socket(connection, server_hostname=host) as tls:
                    leaf = tls.getpeercert(binary_form=True)
            trusted = False
        except (OSError, ValueError):
            result["served"] = "unreachable"
            return result
    except OSError:
        result["served"] = "unreachable"
        return result
    actual = hashlib.sha256(leaf).hexdigest()
    result.update(served="matched" if actual == fingerprint else "mismatch",
                  trusted=trusted, leaf_fingerprint_sha256=actual)
    return result


def enrollment(timer):
    """Observe the subject timer without creating a lock or starting any unit."""
    result = subprocess.run(
        ["systemctl", "show", timer, "--no-pager",
         "--property=LoadState,UnitFileState,ActiveState,NextElapseUSecRealtime"],
        capture_output=True, timeout=3,
    )
    if len(result.stdout) > 8192:
        raise ValueError("timer observation too large")
    fields = dict(line.split("=", 1) for line in result.stdout.decode().splitlines())
    if fields["LoadState"] == "not-found":
        return {"enabled": False, "active": False, "next_due_at": None}
    if result.returncode or fields["LoadState"] != "loaded":
        raise ValueError("timer unavailable")
    enabled = fields["UnitFileState"]
    active = fields["ActiveState"]
    if enabled not in {"enabled", "disabled", "masked", "static", "enabled-runtime"} or active not in {"active", "inactive", "failed"}:
        raise ValueError("timer state unavailable")
    due = fields.get("NextElapseUSecRealtime", "")
    next_due = None
    if due not in {"", "n/a"}:
        parsed = subprocess.run(
            ["date", "--utc", "--date", due, "+%Y-%m-%dT%H:%M:%SZ"],
            capture_output=True, timeout=2, check=True,
        )
        next_due = parsed.stdout.decode().strip()
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", next_due):
            raise ValueError("timer date unavailable")
    return {"enabled": enabled in {"enabled", "enabled-runtime"},
            "active": active == "active", "next_due_at": next_due}


def observe(args, hosts, trust=None):
    """Keep changed selection evidence unavailable rather than mix snapshots."""
    facts, raw = selection(args.selection, args.root, args.subject)
    if facts["source"] == "automatic":
        try:
            facts["renewal"] = enrollment(args.timer)
            facts["outcome"] = "succeeded"
        except (OSError, ValueError, KeyError, subprocess.SubprocessError):
            facts["renewal"] = dict.fromkeys(("enabled", "active", "next_due_at"))
            facts["outcome"] = "incomplete"
    deadline = time.monotonic() + 25
    facts["hosts"] = [probe(host, facts["leaf_fingerprint_sha256"], trust,
                            args.address, args.port, deadline) for host in hosts]
    if any(host["served"] != "matched" or host["trusted"] is not True for host in facts["hosts"]):
        facts["outcome"] = "failed"
    after, after_raw = selection(args.selection, args.root, args.subject)
    if after_raw != raw or snapshot(after) != snapshot(facts):
        raise ValueError("selection changed during observation")
    return facts


def main():
    """Emit bounded plain facts; native errors and paths never reach stdout."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--selection")
    parser.add_argument("--root")
    parser.add_argument("--subject", type=json.loads)
    parser.add_argument("--hosts", type=json.loads, default=[])
    parser.add_argument("--timer")
    parser.add_argument("--address", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--trust-file")
    parser.add_argument("--trust-pem")
    parser.add_argument("--snapshot", action="store_true")
    parser.add_argument("--selection-only", action="store_true")
    parser.add_argument("--require-source", choices=("automatic", "custom", "native"))
    parser.add_argument("--csr")
    parser.add_argument("--revision")
    parser.add_argument("--unused-directory")
    parser.add_argument("--selection-directory")
    args = parser.parse_args()
    facts = empty()
    try:
        if args.selection_only:
            subject_key(args.subject)
            if args.csr or args.unused_directory or args.snapshot or args.hosts:
                raise ValueError("conflicting observation mode")
            print(json.dumps(selection_only(args), separators=(",", ":")))
            return 0
        if args.unused_directory:
            value = referenced(args.selection_directory, args.unused_directory)
            print(json.dumps({"referenced": value}))
            return 0
        if args.csr:
            csr = x509.load_pem_x509_csr(read_file(args.csr, 16 * 1024))
            if not csr.is_signature_valid or not covers(csr, hosts_list(args.hosts)):
                raise ValueError("invalid CSR")
            facts = {"outcome": "succeeded", "observed_at": utc(),
                     "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode("ascii"),
                     "public_key_sha256": hashlib.sha256(public_key(csr.public_key())).hexdigest(),
                     "revision_id": canonical_uuid(args.revision)}
            key = "native_certificate_csr"
        else:
            subject_key(args.subject)
            if not ipaddress.ip_address(args.address).is_loopback or not 1 <= args.port <= 65535:
                raise ValueError("invalid local listener")
            trust = read_file(args.trust_file).decode("ascii") if args.trust_file else args.trust_pem
            if trust is not None and len(trust.encode()) > MAX_MATERIAL:
                raise ValueError("trust too large")
            facts = observe(args, hosts_list(args.hosts), trust)
            key = "certificate_observation"
            if args.require_source and facts["source"] != args.require_source:
                raise ValueError("unexpected selected source")
        result = snapshot(facts) if args.snapshot else {key: facts}
        encoded = json.dumps(result, separators=(",", ":"))
        if len(encoded.encode()) > MAX_OUTPUT:
            raise ValueError("output too large")
        print(encoded)
        return 0 if facts["outcome"] == "succeeded" else 1
    except (OSError, ValueError, TypeError, KeyError, AttributeError, yaml.YAMLError, subprocess.SubprocessError):
        if args.selection_only:
            print(json.dumps(snapshot(empty()), separators=(",", ":")))
            return 1
        print(json.dumps({"certificate_observation": empty(),
                          "procedure_error": {"phase": "observe", "code": "certificate_serving_unverified"}}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
