"""Transactional file-certificate selection for the managed Traefik gateway."""

from contextlib import contextmanager
from datetime import datetime, timezone
import errno
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
import yaml


HEADER = "# opsctl-certificate-selection "
OWNER_FIELDS = {
    "organization_id", "subject", "gateway_id", "server_id", "revision_id",
    "source", "route_hosts", "fingerprint_sha256",
}
IDENTITY_FIELDS = {"organization_id", "subject", "gateway_id", "server_id", "route_hosts"}


class CertificateSelectionError(ValueError):
    """Bounded public refusal; never include key, certificate or arbitrary input."""


def atomic_write(path, content, mode=0o600):
    """Persist one complete file and its directory entry without following links."""
    if path.is_symlink():
        raise CertificateSelectionError("Certificate file ownership is invalid")
    descriptor, temporary = tempfile.mkstemp(prefix=".certificate-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        sync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def subject_key(subject):
    """Keep the two real certificate subjects distinct on a shared Server."""
    if (not isinstance(subject, dict) or set(subject) != {"type", "id"}
            or subject["type"] not in {"deployment", "server"}
            or not isinstance(subject["id"], str)
            or str(UUID(subject["id"])) != subject["id"]):
        raise CertificateSelectionError("Certificate subject is invalid")
    return subject["type"] + "-" + subject["id"]


def validate_identity(owner):
    """Validate qualified ownership without inventing revision or material truth."""
    if not isinstance(owner, dict) or set(owner) != IDENTITY_FIELDS:
        raise CertificateSelectionError("Certificate selection identity is invalid")
    for field in ("organization_id", "server_id"):
        if not isinstance(owner[field], str) or str(UUID(owner[field])) != owner[field]:
            raise CertificateSelectionError("Certificate selection identity is invalid")
    subject_key(owner["subject"])
    if owner["subject"]["type"] == "server":
        if owner["subject"]["id"] != owner["server_id"] or owner["gateway_id"] is not None:
            raise CertificateSelectionError("Server certificate ownership is invalid")
    elif (not isinstance(owner["gateway_id"], str)
            or str(UUID(owner["gateway_id"])) != owner["gateway_id"]):
        raise CertificateSelectionError("Deployment certificate gateway identity is invalid")
    hosts = owner["route_hosts"]
    if (
        not isinstance(hosts, list) or not 1 <= len(hosts) <= 100
        or any(not isinstance(host, str) for host in hosts)
        or hosts != sorted(set(hosts))
    ):
        raise CertificateSelectionError("Certificate selection hosts are invalid")
    for host in hosts:
        if not re.fullmatch(
            r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
            r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*", host,
        ):
            raise CertificateSelectionError("Certificate selection hostname is invalid")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            continue
        raise CertificateSelectionError("Certificate selection requires DNS hostnames")


def validate_owner(owner):
    if not isinstance(owner, dict) or set(owner) != OWNER_FIELDS:
        raise CertificateSelectionError("Certificate selection identity is invalid")
    validate_identity({field: owner[field] for field in IDENTITY_FIELDS})
    if (not isinstance(owner["revision_id"], str)
            or str(UUID(owner["revision_id"])) != owner["revision_id"]):
        raise CertificateSelectionError("Certificate selection identity is invalid")
    if owner["source"] not in {"automatic", "native", "custom"}:
        raise CertificateSelectionError("Certificate selection source is invalid")
    if not re.fullmatch(r"[0-9a-f]{64}", owner["fingerprint_sha256"]):
        raise CertificateSelectionError("Certificate selection fingerprint is invalid")


def layout_metadata(path):
    """Stat one pinned path through descriptor-relative, no-follow parents."""
    result = dict.fromkeys((
        "exists", "is_dir", "is_regular", "is_symlink", "uid_is_root",
        "private_mode", "canonical_path",
    ))
    result["code"] = "unknown"
    if (not isinstance(path, str) or len(path) > 4096
            or not path.startswith("/") or str(Path(path)) != path
            or ".." in Path(path).parts or path == "/"):
        result.update(canonical_path=False, code="noncanonical_path")
        return result
    result["canonical_path"] = True
    descriptor = None
    try:
        descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for part in Path(path).parts[1:-1]:
            next_descriptor = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        value = os.stat(Path(path).name, dir_fd=descriptor, follow_symlinks=False)
        result.update(
            exists=True, is_dir=stat.S_ISDIR(value.st_mode),
            is_regular=stat.S_ISREG(value.st_mode),
            is_symlink=stat.S_ISLNK(value.st_mode), uid_is_root=value.st_uid == 0,
            private_mode=not bool(value.st_mode & 0o077),
            canonical_path=not stat.S_ISLNK(value.st_mode),
            code="symlink" if stat.S_ISLNK(value.st_mode) else "observed",
        )
    except FileNotFoundError:
        result.update(exists=False, code="missing")
    except NotADirectoryError:
        result.update(canonical_path=False, code="unsafe_parent")
    except OSError as error:
        if error.errno == errno.ELOOP:
            result.update(canonical_path=False, code="unsafe_parent")
        else:
            result["code"] = "stat_unavailable"
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return result


def observe_layout(request, state_dir, dynamic_dir):
    """Project only fixed-role metadata, independently of material selection."""
    if not isinstance(request, dict) or set(request) != {"identity", "operation_id"}:
        raise CertificateSelectionError("Certificate selection request is invalid")
    validate_identity(request["identity"])
    operation_id = request["operation_id"]
    if not isinstance(operation_id, str) or str(UUID(operation_id)) != operation_id:
        raise CertificateSelectionError("Certificate selection operation is invalid")
    key = subject_key(request["identity"]["subject"])
    # Preserve the configured spelling: joining must not normalize unsafe roots.
    subject_dir = state_dir + "/" + key
    paths = {
        "acme_root": state_dir,
        "subject_directory": subject_dir,
        "renewal": subject_dir + "/renewal.json",
        "renewal_request": subject_dir + "/renewal-request.json",
        "selected_binding": dynamic_dir + "/certificate-" + key + ".yml",
    }
    return {role: layout_metadata(path) for role, path in paths.items()}


def closed_json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise CertificateSelectionError("Certificate selection evidence is invalid")
        result[key] = value
    return result


def file_identity(path):
    stat = path.stat()
    return (stat.st_dev, stat.st_ino, stat.st_mode, stat.st_size,
            stat.st_mtime_ns, stat.st_ctime_ns)


def matches(host, names):
    wildcard = "*." + host.partition(".")[2]
    return any(name == host or name.rstrip(".") == wildcard for name in names)


def public_key_bytes(value):
    return value.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def validity(leaf, field):
    value = getattr(leaf, field + "_utc", None)
    return value if value is not None else getattr(leaf, field).replace(tzinfo=timezone.utc)


class TraefikCertificateSelection:
    """One atomic record per subject; one Server-wide lock for the loaded TLS pool."""

    def __init__(self, certificate_dir, dynamic_dir):
        self.certificate_dir = Path(certificate_dir)
        self.dynamic_dir = Path(dynamic_dir)
        for path in (self.certificate_dir, self.dynamic_dir):
            if not path.is_absolute() or path.resolve() != path or not path.is_dir():
                raise CertificateSelectionError("Certificate selection layout is invalid")

    @contextmanager
    def locked(self):
        descriptor = os.open(
            self.certificate_dir / ".selection.lock",
            os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600,
        )
        with os.fdopen(descriptor, "rb") as stream:
            fcntl.flock(stream, fcntl.LOCK_EX)
            yield

    def binding(self, owner):
        validate_owner(owner)
        return self.dynamic_dir / f"certificate-{subject_key(owner['subject'])}.yml"

    def _observation_snapshot(self, path, identity):
        """Capture bytes plus file identity, validating expired owned material too."""
        for directory in (self.certificate_dir, self.dynamic_dir):
            if directory.resolve() != directory or not directory.is_dir():
                raise CertificateSelectionError("Certificate selection layout is invalid")
        if path.is_symlink():
            raise CertificateSelectionError("Certificate selection record is invalid")
        if not path.exists():
            return None
        before = file_identity(path)
        selected = self.read(path, require_current_validity=False)
        if any(selected["owner"][field] != identity[field]
               for field in IDENTITY_FIELDS - {"route_hosts"}):
            raise CertificateSelectionError("Certificate selection ownership changed")
        raw = path.read_bytes()
        if not 1 <= len(raw) <= 65536:
            raise CertificateSelectionError("Certificate selection record is invalid")
        header, separator, body = raw.decode("ascii").partition("\n")
        if not separator or not header.startswith(HEADER):
            raise CertificateSelectionError("Certificate selection record is invalid")
        owner = json.loads(header[len(HEADER):], object_pairs_hook=closed_json_pairs)
        document = json.loads(body, object_pairs_hook=closed_json_pairs)
        if owner != selected["owner"]:
            raise CertificateSelectionError("Certificate selection changed during observation")
        files = document["tls"]["certificates"][0]
        material = []
        for field in ("certFile", "keyFile"):
            file = Path(files[field])
            stat = file_identity(file)
            material.append((stat, hashlib.sha256(file.read_bytes()).digest()))
        if path.is_symlink() or file_identity(path) != before:
            raise CertificateSelectionError("Certificate selection changed during observation")
        return raw, before, material

    def observe(self, request):
        """Return read-only byte CAS evidence with a stable material snapshot."""
        if not isinstance(request, dict) or set(request) != {"identity", "operation_id"}:
            raise CertificateSelectionError("Certificate selection request is invalid")
        identity = request["identity"]
        validate_identity(identity)
        operation_id = request["operation_id"]
        if not isinstance(operation_id, str) or str(UUID(operation_id)) != operation_id:
            raise CertificateSelectionError("Certificate selection operation is invalid")
        path = self.dynamic_dir / f"certificate-{subject_key(identity['subject'])}.yml"
        snapshot = self._observation_snapshot(path, identity)
        if self._observation_snapshot(path, identity) != snapshot:
            raise CertificateSelectionError("Certificate selection changed during observation")
        result = {
            "identity": identity,
            "operation_id": operation_id,
            "expected_binding": snapshot[0].decode("ascii") if snapshot else None,
        }
        result["digest"] = hashlib.sha256(
            json.dumps(result, sort_keys=True, separators=(",", ":")).encode(),
        ).hexdigest()
        return {"automatic_certificate_selection": result}

    def observe_custom(self, request):
        """Project custom material only from an unchanged canonical selection."""
        if not isinstance(request, dict) or set(request) != {"identity"}:
            raise CertificateSelectionError("Custom certificate observation request is invalid")
        identity = request["identity"]
        validate_identity(identity)
        path = self.dynamic_dir / f"certificate-{subject_key(identity['subject'])}.yml"
        snapshot = self._observation_snapshot(path, identity)
        result = {"present": False, "expected_binding": None}
        if snapshot is not None:
            selected = self.read(path, require_current_validity=False)
            owner = selected["owner"]
            if owner["source"] != "custom" or owner["route_hosts"] != identity["route_hosts"]:
                raise CertificateSelectionError("Custom certificate selection ownership is invalid")
            document = json.loads(snapshot[0].decode("ascii").partition("\n")[2],
                                  object_pairs_hook=closed_json_pairs)
            files = document["tls"]["certificates"][0]
            relative = Path(files["certFile"]).relative_to(self.certificate_dir)
            if (len(relative.parts) != 3 or relative.parts[2] != "tls.crt"
                    or not relative.parts[0].startswith("material-")
                    or relative.parts[1] != "revision-" + owner["revision_id"]):
                raise CertificateSelectionError("Custom certificate material layout is invalid")
            material_id = relative.parts[0].removeprefix("material-")
            if str(UUID(material_id)) != material_id:
                raise CertificateSelectionError("Custom certificate material identity is invalid")
            if Path(files["keyFile"]) != Path(files["certFile"]).with_name("tls.key"):
                raise CertificateSelectionError("Custom certificate key identity is invalid")
            digest = hashlib.sha256(b"opsctl-file-secret:1\0")
            for name in ("tls.crt", "tls.key"):
                encoded = name.encode("ascii")
                value = Path(files["certFile"]).with_name(name).read_bytes()
                digest.update(len(encoded).to_bytes(2, "big"))
                digest.update(encoded)
                digest.update(len(value).to_bytes(8, "big"))
                digest.update(value)
            result = {"present": True, "expected_binding": snapshot[0].decode("ascii"),
                      "material_id": material_id, "revision_id": owner["revision_id"],
                      "route_hosts": owner["route_hosts"], "content_digest": digest.hexdigest(),
                      "leaf_fingerprint_sha256": owner["fingerprint_sha256"]}
        if self._observation_snapshot(path, identity) != snapshot:
            raise CertificateSelectionError("Custom certificate evidence changed during observation")
        return {"custom_certificate_binding": result}

    def material(self, owner, certificate_file, private_key_file, require_current_validity=True):
        validate_owner(owner)
        paths = [Path(certificate_file), Path(private_key_file)]
        for path in paths:
            if (
                not path.is_absolute() or path.resolve() != path
                or not path.is_relative_to(self.certificate_dir) or not path.is_file()
                or path.stat().st_mode & 0o077
            ):
                raise CertificateSelectionError("Selected certificate files are invalid")
        leaf = x509.load_pem_x509_certificate(paths[0].read_bytes())
        key = serialization.load_pem_private_key(paths[1].read_bytes(), password=None)
        if (
            leaf.fingerprint(hashes.SHA256()).hex() != owner["fingerprint_sha256"]
            or public_key_bytes(leaf.public_key()) != public_key_bytes(key.public_key())
            or validity(leaf, "not_valid_before") > datetime.now(timezone.utc)
            or (require_current_validity and datetime.now(timezone.utc) >= validity(leaf, "not_valid_after"))
        ):
            raise CertificateSelectionError("Selected certificate material identity is invalid")
        sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        dns_names = sans.get_values_for_type(x509.DNSName)
        if not all(matches(host, [value.lower() for value in dns_names]) for host in owner["route_hosts"]):
            raise CertificateSelectionError("Selected certificate does not cover its hostnames")
        common_names = leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        common_name = common_names[0].value if common_names else ""
        names = [common_name.lower()] if common_name else []
        names.extend(value.lower() for value in dns_names if value != common_name)
        names.extend(str(value) for value in sans.get_values_for_type(x509.IPAddress)
                     if str(value) != common_name)
        return {"owner": owner, "names": names, "key": ",".join(sorted(names))}

    def document(self, owner, certificate_file, private_key_file):
        self.material(owner, certificate_file, private_key_file)
        metadata = json.dumps(owner, sort_keys=True, separators=(",", ":"))
        body = {"tls": {"certificates": [{
            "certFile": str(certificate_file), "keyFile": str(private_key_file),
        }]}}
        return (HEADER + metadata + "\n" + json.dumps(body, sort_keys=True) + "\n").encode()

    def read(self, path, require_current_validity=True):
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
            raise CertificateSelectionError("Certificate selection record is invalid")
        raw = path.read_bytes()
        header, _, body = raw.decode("ascii").partition("\n")
        if not header.startswith(HEADER):
            raise CertificateSelectionError("Unowned certificate pool requires reconciliation")
        owner = json.loads(header[len(HEADER):])
        if path != self.binding(owner):
            raise CertificateSelectionError("Certificate selection owner changed")
        parsed = json.loads(body)
        if (
            not isinstance(parsed, dict) or set(parsed) != {"tls"}
            or not isinstance(parsed["tls"], dict) or set(parsed["tls"]) != {"certificates"}
            or not isinstance(parsed["tls"]["certificates"], list)
            or len(parsed["tls"]["certificates"]) != 1
        ):
            raise CertificateSelectionError("Certificate selection binding is invalid")
        files = parsed["tls"]["certificates"][0]
        if not isinstance(files, dict) or set(files) != {"certFile", "keyFile"}:
            raise CertificateSelectionError("Certificate selection files are invalid")
        return self.material(owner, files["certFile"], files["keyFile"], require_current_validity)

    def pool(self, owner, candidate):
        selections = []
        binding = self.binding(owner)
        for path in sorted(self.dynamic_dir.iterdir()):
            if path.suffix not in {".yml", ".yaml", ".toml"} or path.name.startswith("."):
                continue
            if path == binding:
                continue
            if path.name.startswith("certificate-"):
                selection = self.read(path, require_current_validity=False)
                if any(selection["owner"][field] != owner[field] for field in ("organization_id", "server_id")):
                    raise CertificateSelectionError("Certificate pool gateway ownership changed")
                selections.append(selection)
                continue
            if path.is_symlink() or path.stat().st_size > 1048576:
                raise CertificateSelectionError("Gateway TLS configuration is invalid")
            if path.suffix == ".toml":
                import tomllib
                config = tomllib.loads(path.read_text())
            else:
                config = yaml.safe_load(path.read_text())
            if not isinstance(config, dict):
                raise CertificateSelectionError("Gateway TLS configuration is invalid")
            tls = config.get("tls", {})
            if not isinstance(tls, dict) or tls.get("certificates") or tls.get("stores"):
                raise CertificateSelectionError("Unowned certificate pool requires reconciliation")
        if candidate is not None:
            selections.append(candidate)
        self.validate_pool(selections)

    @staticmethod
    def validate_pool(selections):
        pool = {}
        desired = {}
        for selection in selections:
            owner = selection["owner"]
            pool.setdefault(selection["key"], set()).add(owner["fingerprint_sha256"])
            for host in owner["route_hosts"]:
                if host in desired:
                    raise CertificateSelectionError("Certificate hostname has multiple owners: " + host)
                desired[host] = owner["fingerprint_sha256"]
        for host, fingerprint in desired.items():
            keys = [key for key in pool if matches(host, key.split(","))]
            if not keys or pool[max(keys)] != {fingerprint}:
                raise CertificateSelectionError(
                    "Traefik cannot select the intended certificate for " + host
                    + "; use non-conflicting certificate ownership or a separate gateway",
                )

    def activate(self, owner, certificate_file, private_key_file, expected, verify):
        """CAS, validate the complete pool, activate, verify and restore under one lock."""
        candidate = self.material(owner, certificate_file, private_key_file)
        desired = self.document(owner, certificate_file, private_key_file)
        path = self.binding(owner)
        with self.locked():
            if path.is_symlink():
                raise CertificateSelectionError("Certificate binding ownership is invalid")
            previous = path.read_bytes() if path.exists() else None
            if previous not in (expected, desired):
                raise CertificateSelectionError("Certificate binding changed before activation")
            self.pool(owner, candidate)
            try:
                if previous != desired:
                    atomic_write(path, desired, 0o644)
                verify()
            except Exception:
                if previous is None:
                    path.unlink(missing_ok=True)
                    sync_directory(path.parent)
                elif previous != desired:
                    atomic_write(path, previous, 0o644)
                raise

    def remove(self, owner, expected):
        """Remove only the exact owned binding without changing another selection."""
        path = self.binding(owner)
        with self.locked():
            if not path.exists() and not path.is_symlink():
                return
            selection = self.read(path, require_current_validity=False)
            if selection["owner"] != owner or path.read_bytes() != expected:
                raise CertificateSelectionError("Certificate binding changed before removal")
            self.pool(owner, None)
            path.unlink()
            sync_directory(path.parent)


def main():
    request = json.loads(sys.stdin.buffer.read(65537))
    if sys.argv[1] == "observe_layout":
        result = observe_layout(
            request, os.environ["OPSCTL_ACME_STATE_DIR"], os.environ["OPSCTL_DYNAMIC_DIR"],
        )
        print("CERTIFICATE_LAYOUT_METADATA=" + json.dumps(result, sort_keys=True))
        return
    selection = TraefikCertificateSelection(
        os.environ["OPSCTL_CERTIFICATE_DIR"], os.environ["OPSCTL_DYNAMIC_DIR"],
    )
    if sys.argv[1] == "observe":
        print("TEMPLATE_OUTPUT_JSON=" + json.dumps(selection.observe(request)))
        return
    if sys.argv[1] == "observe_custom":
        print("TEMPLATE_OUTPUT_JSON=" + json.dumps(selection.observe_custom(request)))
        return
    owner = request["owner"]
    expected = request["expected_binding"]
    expected = expected.encode("ascii") if expected is not None else None
    if sys.argv[1] == "activate":
        selection.activate(owner, request["certificate_file"], request["private_key_file"],
                           expected, lambda: None)
    elif sys.argv[1] == "remove":
        selection.remove(owner, expected)
    else:
        raise CertificateSelectionError("Certificate selection action is invalid")


if __name__ == "__main__":
    try:
        main()
    except CertificateSelectionError as error:
        sys.exit(str(error))
    except Exception:
        sys.exit("Certificate selection execution failed")
