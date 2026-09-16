#!/usr/bin/env python3
"""Observe and converge UUID-owned Caddy Deployment routes."""

from __future__ import annotations

import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from urllib.request import urlopen
from uuid import UUID


HEADER_PREFIX = b"# opsctl-managed-caddy-route-v2 "
AUTOMATIC_ADAPTER = "caddy_acme_http01"
CUSTOM_ADAPTER = "caddy_custom_file"
DIGEST_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
HOSTNAME_PATTERN = re.compile(
    r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\Z"
)


def canonical_uuid(value: object) -> str:
    if not isinstance(value, str) or str(UUID(value)) != value:
        raise ValueError("Caddy route identity is invalid")
    return value


def valid_hosts(value: object) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and all(
            isinstance(host, str) and HOSTNAME_PATTERN.fullmatch(host)
            for host in value
        )
        and value == sorted(set(value))
    )


def tls_binding(value: object, use_https: bool) -> dict[str, object] | None:
    if not use_https:
        if value is not None:
            raise ValueError("HTTP route has a certificate binding")
        return None
    if not isinstance(value, dict) or set(value) != {
        "mode", "adapter_key", "material_id", "revision_id",
    }:
        raise ValueError("Caddy route certificate binding is invalid")
    mode = value.get("mode")
    if mode == "automatic":
        if (
            value.get("adapter_key") != AUTOMATIC_ADAPTER
            or value.get("material_id") is not None
            or value.get("revision_id") is not None
        ):
            raise ValueError("Caddy automatic route binding is invalid")
    elif mode == "custom":
        if value.get("adapter_key") != CUSTOM_ADAPTER:
            raise ValueError("Caddy custom route binding is invalid")
        canonical_uuid(value.get("material_id"))
        canonical_uuid(value.get("revision_id"))
    else:
        raise ValueError("Caddy route certificate mode is invalid")
    return dict(value)


def route_body(
    hosts: list[str],
    port: int,
    use_https: bool,
    redirect: bool,
    binding: dict[str, object] | None,
) -> bytes:
    address = ", ".join(hosts)
    backend = f"reverse_proxy 127.0.0.1:{port}"
    if not use_https:
        value = ", ".join("http://" + host for host in hosts)
        return f"{value} {{\n  {backend}\n}}\n".encode()
    normalized = tls_binding(binding, use_https)
    if normalized["mode"] == "automatic":
        tls_line = "tls force_automate"
    else:
        material_id = normalized["material_id"]
        revision_id = normalized["revision_id"]
        base = (
            "/etc/caddy/opsctl-certificates/"
            f"material-{material_id}/revision-{revision_id}"
        )
        tls_line = f"tls {base}/tls.crt {base}/tls.key"
    result = f"{address} {{\n  {tls_line}\n  {backend}\n}}\n"
    http_address = ", ".join("http://" + host for host in hosts)
    if redirect:
        result += (
            f"{http_address} {{\n"
            "  @non_challenge not path /.well-known/acme-challenge/*\n"
            "  redir @non_challenge https://{host}{uri} 301\n"
            "}\n"
        )
    else:
        result += f"{http_address} {{\n  {backend}\n}}\n"
    return result.encode()


def observation(identity: dict[str, object] | None) -> dict[str, object]:
    if identity is None:
        value: dict[str, object] = {
            "presence": "absent",
            "hosts": [],
            "route_port": None,
            "https": None,
            "redirect_http_to_https": None,
            "middlewares": [],
            "backend_identity_class": None,
            "tls_binding": None,
        }
    else:
        value = {
            "presence": "present",
            "hosts": identity["route_hosts"],
            "route_port": identity["route_port"],
            "https": identity["route_https"],
            "redirect_http_to_https": identity["redirect_http_to_https"],
            "middlewares": [],
            "backend_identity_class": "loopback",
            "tls_binding": identity["route_tls_binding"],
        }
    value["digest"] = hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return value


def unknown_observation() -> dict[str, object]:
    value: dict[str, object] = {
        "presence": "unknown",
        "hosts": [],
        "route_port": None,
        "https": None,
        "redirect_http_to_https": None,
        "middlewares": [],
        "backend_identity_class": None,
        "tls_binding": None,
    }
    value["digest"] = hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return value


class CaddyRouteContract:
    """Sole parser, observer, and compare-before-apply route owner."""

    def __init__(
        self,
        *,
        state_path: Path = Path("/etc/opsctl/caddy-proxy.json"),
        config_path: Path = Path("/etc/caddy/Caddyfile"),
        route_dir: Path = Path("/etc/caddy/opsctl-routes"),
        lock_path: Path = Path("/etc/opsctl/caddy-route.lock"),
        admin_url: str = "http://127.0.0.1:2019/config/",
        certificate_dir: Path = Path("/etc/caddy/opsctl-certificates"),
    ) -> None:
        self.state_path = state_path
        self.config_path = config_path
        self.route_dir = route_dir
        self.lock_path = lock_path
        self.admin_url = admin_url
        self.certificate_dir = certificate_dir

    @staticmethod
    def parse_route(path: Path) -> tuple[dict[str, object], bytes]:
        if path.is_symlink() or not path.is_file():
            raise ValueError("Unrecognized Caddy route file")
        raw = path.read_bytes()
        header, separator, body = raw.partition(b"\n")
        if not separator or not header.startswith(HEADER_PREFIX):
            raise ValueError("Unrecognized legacy or UUID Caddy route")
        try:
            identity = json.loads(header[len(HEADER_PREFIX):])
            deployment = canonical_uuid(identity["deployment_id"])
            canonical_uuid(identity["organization_id"])
            hosts = identity["route_hosts"]
            port = identity["route_port"]
            use_https = identity["route_https"]
            redirect = identity["redirect_http_to_https"]
            binding = tls_binding(identity["route_tls_binding"], use_https)
            digest = identity["body_sha256"]
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("Managed Caddy route identity is invalid") from exc
        if (
            set(identity) != {
                "deployment_id", "organization_id", "route_hosts", "route_port",
                "route_https", "redirect_http_to_https", "body_sha256",
                "route_tls_binding",
            }
            or path.name != f"{deployment}.caddy"
            or not valid_hosts(hosts)
            or not isinstance(port, int)
            or isinstance(port, bool)
            or not 1 <= port <= 65535
            or not isinstance(use_https, bool)
            or not isinstance(redirect, bool)
            or (redirect and not use_https)
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or hashlib.sha256(body).hexdigest() != digest
            or body != route_body(hosts, port, use_https, redirect, binding)
        ):
            raise ValueError("Managed Caddy route content is invalid")
        return identity, raw

    @staticmethod
    def render_route(
        deployment_id: str,
        organization_id: str,
        hosts: list[str],
        port: int,
        use_https: bool,
        redirect: bool,
        binding: dict[str, object] | None,
    ) -> bytes:
        normalized_binding = tls_binding(binding, use_https)
        body = route_body(hosts, port, use_https, redirect, normalized_binding)
        identity = {
            "deployment_id": deployment_id,
            "organization_id": organization_id,
            "route_hosts": hosts,
            "route_port": port,
            "route_https": use_https,
            "redirect_http_to_https": redirect,
            "route_tls_binding": normalized_binding,
            "body_sha256": hashlib.sha256(body).hexdigest(),
        }
        return (
            HEADER_PREFIX
            + json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
            + b"\n"
            + body
        )

    def run_caddy(self, *arguments: str) -> str:
        result = subprocess.run(
            ["caddy", *arguments],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode != 0:
            raise RuntimeError("Caddy validation or reload failed")
        return result.stdout

    def adapted(self, path: Path) -> dict[str, object]:
        value = json.loads(
            self.run_caddy("adapt", "--config", str(path), "--adapter", "caddyfile")
        )
        if not isinstance(value, dict):
            raise RuntimeError("Caddy adapted configuration is invalid")
        return value

    def live_config(self) -> dict[str, object]:
        with urlopen(self.admin_url, timeout=5) as response:
            value = json.load(response)
        if not isinstance(value, dict):
            raise RuntimeError("Running Caddy configuration is invalid")
        return value

    def verify_live(self, path: Path) -> None:
        if self.live_config() != self.adapted(path):
            raise RuntimeError("Running Caddy configuration differs from managed source")

    def _validate_gateway(self, organization_id: str) -> tuple[bytes, str]:
        if (
            self.state_path.is_symlink()
            or self.config_path.is_symlink()
            or self.route_dir.is_symlink()
            or not self.state_path.is_file()
            or not self.config_path.is_file()
            or not self.route_dir.is_dir()
        ):
            raise ValueError("Managed Caddy gateway state is unavailable")
        state_raw = self.state_path.read_bytes()
        state = json.loads(state_raw)
        if (
            not isinstance(state, dict)
            or state.get("engine") != "caddy"
            or state.get("managed") is not True
            or state.get("org_id") != organization_id
        ):
            raise ValueError("Caddy gateway ownership differs from route intent")
        source = self.config_path.read_text()
        import_line = f"import {self.route_dir}/*.caddy"
        if source.splitlines().count(import_line) != 1:
            raise ValueError("Managed Caddy import is missing or ambiguous")
        return state_raw, source

    def _routes(self, organization_id: str) -> dict[str, tuple[dict[str, object], bytes]]:
        paths = sorted(self.route_dir.iterdir())
        if any(path.suffix != ".caddy" for path in paths):
            raise ValueError("Unrecognized Caddy route file")
        routes = {}
        host_owners: dict[str, str] = {}
        for path in paths:
            identity, raw = self.parse_route(path)
            if identity["organization_id"] != organization_id:
                raise ValueError("Caddy route belongs to another organization")
            deployment_id = str(identity["deployment_id"])
            for host in identity["route_hosts"]:
                owner = host_owners.setdefault(host, deployment_id)
                if owner != deployment_id:
                    raise ValueError("Caddy route hostname ownership is ambiguous")
            routes[path.name] = (identity, raw)
        return routes

    def _lock(self) -> int:
        descriptor = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        return descriptor

    @staticmethod
    def _unlock(descriptor: int) -> None:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)

    def observe(self, deployment_id: str, organization_id: str) -> dict[str, object]:
        descriptor = self._lock()
        try:
            self._validate_gateway(organization_id)
            routes = self._routes(organization_id)
            self.verify_live(self.config_path)
            target = routes.get(f"{deployment_id}.caddy")
            return observation(target[0] if target is not None else None)
        finally:
            self._unlock(descriptor)

    def _write_atomic(
        self,
        target: Path,
        content: bytes,
        directory: Path,
        mode: int = 0o644,
    ) -> None:
        temporary = directory / f".{target.name}.tmp"
        temporary.write_bytes(content)
        os.chmod(temporary, mode)
        os.replace(temporary, target)

    def _verify_snapshot(
        self,
        state_raw: bytes,
        source: str,
        expected: dict[str, bytes],
    ) -> None:
        actual_names = {path.name for path in self.route_dir.iterdir()}
        if (
            self.state_path.read_bytes() != state_raw
            or self.config_path.read_text() != source
            or actual_names != set(expected)
            or any((self.route_dir / name).read_bytes() != raw for name, raw in expected.items())
        ):
            raise RuntimeError("Caddy route files changed unexpectedly")

    def converge(
        self,
        *,
        deployment_id: str,
        organization_id: str,
        execution_contract: str,
        expected_observation: dict[str, object] | None,
        route_state: str,
        hosts: list[str],
        port: int,
        use_https: bool,
        redirect: bool,
        binding: dict[str, object] | None,
    ) -> str:
        if (
            execution_contract not in {"deploy", "configuration"}
            or route_state not in {"present", "absent"}
            or (route_state == "present" and not valid_hosts(hosts))
            or (route_state == "absent" and hosts != [])
            or not isinstance(port, int)
            or isinstance(port, bool)
            or not 1 <= port <= 65535
            or not isinstance(use_https, bool)
            or not isinstance(redirect, bool)
            or (redirect and not use_https)
            or tls_binding(binding, use_https) != binding
            or (execution_contract == "configuration") != (expected_observation is not None)
        ):
            raise ValueError("Caddy route policy is invalid")
        descriptor = self._lock()
        try:
            state_raw, source = self._validate_gateway(organization_id)
            routes = self._routes(organization_id)
            self.verify_live(self.config_path)
            target = self.route_dir / f"{deployment_id}.caddy"
            previous = routes.get(target.name)
            current = observation(previous[0] if previous is not None else None)
            if execution_contract == "configuration" and expected_observation != current:
                raise RuntimeError("Caddy route changed before convergence")
            if route_state == "present":
                desired = self.render_route(
                    deployment_id,
                    organization_id,
                    hosts,
                    port,
                    use_https,
                    redirect,
                    binding,
                )
                for name, (identity, _raw) in routes.items():
                    if name != target.name and set(hosts) & set(identity["route_hosts"]):
                        raise ValueError("Caddy route hostname is already owned")
            else:
                desired = None
            previous_raw = previous[1] if previous is not None else None
            if previous_raw == desired:
                return "noop"
            original = {name: raw for name, (_identity, raw) in routes.items()}
            candidate_routes = dict(original)
            if desired is None:
                candidate_routes.pop(target.name, None)
            else:
                candidate_routes[target.name] = desired
            with tempfile.TemporaryDirectory(
                prefix=".opsctl-caddy-route-",
                dir=str(self.config_path.parent),
            ) as temporary:
                stage = Path(temporary)
                stage_routes = stage / "routes"
                stage_routes.mkdir(mode=0o700)
                for name, raw in candidate_routes.items():
                    (stage_routes / name).write_bytes(raw)
                staged_config = stage / "Caddyfile"
                staged_config.write_text(
                    source.replace(
                        str(self.route_dir) + "/*.caddy",
                        str(stage_routes) + "/*.caddy",
                    )
                )
                self.run_caddy(
                    "validate", "--config", str(staged_config), "--adapter", "caddyfile"
                )
                candidate = self.adapted(staged_config)
                self._verify_snapshot(state_raw, source, original)
                activated = False
                try:
                    if desired is None:
                        target.unlink()
                    else:
                        self._write_atomic(target, desired, stage)
                    activated = True
                    self.run_caddy(
                        "reload", "--config", str(self.config_path), "--adapter", "caddyfile"
                    )
                    self.verify_live(self.config_path)
                    if self.adapted(self.config_path) != candidate:
                        raise RuntimeError("Activated Caddy route differs from staged candidate")
                    self._verify_snapshot(state_raw, source, candidate_routes)
                except Exception:
                    if activated:
                        try:
                            if previous_raw is None:
                                target.unlink(missing_ok=True)
                            else:
                                self._write_atomic(target, previous_raw, stage)
                            self.run_caddy(
                                "reload", "--config", str(self.config_path),
                                "--adapter", "caddyfile",
                            )
                            self.verify_live(self.config_path)
                            self._verify_snapshot(state_raw, source, original)
                        except Exception as exc:
                            print("CADDY_ROUTE_RESULT=cleanup_liability")
                            raise RuntimeError("Caddy route restoration is unverified") from exc
                        print("CADDY_ROUTE_RESULT=failed_restored")
                    raise
            return "changed"
        finally:
            self._unlock(descriptor)

    @staticmethod
    def _file_secret_digest(files: dict[str, bytes]) -> str:
        digest = hashlib.sha256()
        digest.update(b"opsctl-file-secret:1\0")
        for name in sorted(files):
            encoded = name.encode("ascii")
            value = files[name]
            digest.update(len(encoded).to_bytes(2, "big"))
            digest.update(encoded)
            digest.update(len(value).to_bytes(8, "big"))
            digest.update(value)
        return digest.hexdigest()

    @staticmethod
    def _certificate_fingerprint(chain: bytes) -> str:
        match = re.search(
            br"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            chain,
            re.DOTALL,
        )
        if match is None:
            raise ValueError("Certificate chain is invalid")
        der = ssl.PEM_cert_to_DER_cert(match.group().decode("ascii"))
        return hashlib.sha256(der).hexdigest()

    @staticmethod
    def _openssl(*arguments: str, input_value: bytes | None = None) -> bytes:
        result = subprocess.run(
            ["openssl", *arguments],
            input=input_value,
            capture_output=True,
            timeout=15,
        )
        if result.returncode != 0:
            raise ValueError("Certificate material validation failed")
        return result.stdout

    def _validate_material(
        self,
        chain_path: Path,
        key_path: Path,
        hosts: list[str],
        content_digest: str,
        fingerprint: str,
        service_group_id: int | None = None,
    ) -> dict[str, bytes]:
        if any(path.is_symlink() or not path.is_file() for path in (chain_path, key_path)):
            raise ValueError("Certificate material source is invalid")
        if service_group_id is not None:
            for directory in (
                self.certificate_dir,
                chain_path.parent.parent,
                chain_path.parent,
            ):
                stat = directory.stat()
                if (
                    directory.is_symlink()
                    or not directory.is_dir()
                    or stat.st_uid != 0
                    or stat.st_gid != service_group_id
                    or stat.st_mode & 0o777 != 0o710
                ):
                    raise ValueError("Certificate material permissions are invalid")
            for path in (chain_path, key_path):
                stat = path.stat()
                if (
                    stat.st_uid != 0
                    or stat.st_gid != service_group_id
                    or stat.st_mode & 0o777 != 0o640
                ):
                    raise ValueError("Certificate material permissions are invalid")
        files = {"tls.crt": chain_path.read_bytes(), "tls.key": key_path.read_bytes()}
        if (
            self._file_secret_digest(files) != content_digest
            or self._certificate_fingerprint(files["tls.crt"]) != fingerprint
        ):
            raise ValueError("Certificate material identity differs")
        certificate_key = self._openssl("x509", "-pubkey", "-noout", input_value=files["tls.crt"])
        private_key = self._openssl("pkey", "-pubout", input_value=files["tls.key"])
        if certificate_key != private_key:
            raise ValueError("Certificate private key differs")
        for host in hosts:
            self._openssl("x509", "-noout", "-checkhost", host, input_value=files["tls.crt"])
        return files

    @staticmethod
    def _service_group_id() -> int:
        result = subprocess.run(
            ["systemctl", "show", "--property=Group", "--value", "caddy.service"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        group_name = result.stdout.strip()
        if result.returncode != 0 or not group_name:
            raise ValueError("Caddy service group is unavailable")
        try:
            return grp.getgrnam(group_name).gr_gid
        except KeyError as exc:
            raise ValueError("Caddy service group is unavailable") from exc

    @staticmethod
    def _prepare_directory(path: Path, group_id: int) -> None:
        if path.exists() and (path.is_symlink() or not path.is_dir()):
            raise ValueError("Caddy certificate directory is invalid")
        path.mkdir(mode=0o710, parents=True, exist_ok=True)
        os.chown(path, 0, group_id)
        os.chmod(path, 0o710)

    @staticmethod
    def _write_manifest(path: Path, value: bytes) -> None:
        if path.is_symlink():
            raise ValueError("Caddy certificate manifest is invalid")
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            dir=str(path.parent),
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = -1
                stream.write(value)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            temporary.unlink(missing_ok=True)

    @staticmethod
    def _probe_hosts(hosts: list[str], renewal_due_days: int) -> list[dict[str, object]]:
        import socket
        import ssl

        now = datetime.now(timezone.utc)
        values = []
        for host in hosts:
            status = "unknown"
            trusted = None
            fingerprint = None
            not_before = None
            not_after = None
            renewal_due = None
            try:
                context = ssl.create_default_context()
                with socket.create_connection(("127.0.0.1", 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as tls:
                        metadata = tls.getpeercert()
                        der = tls.getpeercert(binary_form=True)
                before = datetime.fromtimestamp(
                    ssl.cert_time_to_seconds(metadata["notBefore"]), timezone.utc
                )
                after = datetime.fromtimestamp(
                    ssl.cert_time_to_seconds(metadata["notAfter"]), timezone.utc
                )
                trusted = True
                fingerprint = hashlib.sha256(der).hexdigest()
                not_before = before.strftime("%Y-%m-%dT%H:%M:%SZ")
                not_after = after.strftime("%Y-%m-%dT%H:%M:%SZ")
                renewal_due = (after - now).total_seconds() <= renewal_due_days * 86400
                status = "renewal_due" if renewal_due else "active"
            except ssl.SSLCertVerificationError:
                trusted = False
                status = "hostname_mismatch"
                try:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    with socket.create_connection(("127.0.0.1", 443), timeout=5) as sock:
                        with context.wrap_socket(sock, server_hostname=host) as tls:
                            der = tls.getpeercert(binary_form=True)
                    fingerprint = hashlib.sha256(der).hexdigest()
                except (OSError, ssl.SSLError, ValueError):
                    status = "unknown"
                    trusted = None
                    fingerprint = None
            except (OSError, ssl.SSLError, KeyError, ValueError):
                pass
            values.append({
                "hostname": host,
                "status": status,
                "trusted": trusted,
                "fingerprint_sha256": fingerprint,
                "not_before": not_before,
                "not_after": not_after,
                "renewal_due": renewal_due,
            })
        return values

    @staticmethod
    def _certificate_status(
        configured: bool,
        bound: bool,
        hosts: list[dict[str, object]],
    ) -> str:
        statuses = {item["status"] for item in hosts}
        if statuses == {"unknown"}:
            return "unknown"
        if not configured:
            return "not_configured"
        if not bound:
            return "installation_failed"
        for status in (
            "expired", "hostname_mismatch", "installation_failed",
            "renewal_failed", "unknown", "pending", "renewal_due",
        ):
            if status in statuses:
                return status
        return "active" if statuses == {"active"} else "unknown"

    def automatic_observation(
        self,
        deployment_id: str,
        organization_id: str,
        hosts: list[str],
        renewal_due_days: int,
    ) -> dict[str, object]:
        descriptor = self._lock()
        try:
            self._validate_gateway(organization_id)
            routes = self._routes(organization_id)
            self.verify_live(self.config_path)
            target = routes.get(f"{deployment_id}.caddy")
            identity = target[0] if target else None
            configured = True
            bound = bool(
                identity
                and identity["route_hosts"] == hosts
                and identity["route_tls_binding"] == {
                    "mode": "automatic",
                    "adapter_key": AUTOMATIC_ADAPTER,
                    "material_id": None,
                    "revision_id": None,
                }
            )
            observed_hosts = self._probe_hosts(hosts, renewal_due_days)
        finally:
            self._unlock(descriptor)
        value = {
            "adapter_key": AUTOMATIC_ADAPTER,
            "mode": "automatic",
            "route_hosts": hosts,
            "challenge_type": "http-01",
            "resolver_configured": configured,
            "resolver_bound": bound,
            "status": self._certificate_status(configured, bound, observed_hosts),
            "hosts": observed_hosts,
            "observed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        value["digest"] = hashlib.sha256(
            json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return value

    def _manifest_path(self, deployment_id: str) -> Path:
        return self.certificate_dir / f"deployment-{deployment_id}.json"

    def _read_manifest(self, deployment_id: str) -> dict[str, object] | None:
        path = self._manifest_path(deployment_id)
        if path.is_symlink():
            raise ValueError("Caddy certificate manifest is invalid")
        if not path.exists():
            return None
        if not path.is_file():
            raise ValueError("Caddy certificate manifest is invalid")
        stat = path.stat()
        if stat.st_uid != 0 or stat.st_gid != 0 or stat.st_mode & 0o777 != 0o600:
            raise ValueError("Caddy certificate manifest permissions are invalid")
        value = json.loads(path.read_bytes())
        expected = {
            "adapter_key", "deployment_id", "material_id", "revision_id",
            "route_hosts", "metadata_digest", "content_digest",
            "leaf_fingerprint_sha256",
        }
        if not isinstance(value, dict) or set(value) != expected:
            raise ValueError("Caddy certificate manifest is invalid")
        canonical_uuid(value["deployment_id"])
        canonical_uuid(value["material_id"])
        canonical_uuid(value["revision_id"])
        if (
            value["adapter_key"] != CUSTOM_ADAPTER
            or value["deployment_id"] != deployment_id
            or not valid_hosts(value["route_hosts"])
            or any(DIGEST_PATTERN.fullmatch(value[key]) is None for key in (
                "metadata_digest", "content_digest", "leaf_fingerprint_sha256"
            ))
        ):
            raise ValueError("Caddy certificate manifest is invalid")
        return value

    def _custom_observation_locked(
        self,
        deployment_id: str,
        organization_id: str,
        requested: dict[str, object],
    ) -> dict[str, object]:
        self._validate_gateway(organization_id)
        routes = self._routes(organization_id)
        self.verify_live(self.config_path)
        manifest = self._read_manifest(deployment_id)
        route = routes.get(f"{deployment_id}.caddy")
        route_binding = route[0]["route_tls_binding"] if route else None
        custom_route_binding = (
            route_binding
            if isinstance(route_binding, dict)
            and route_binding.get("mode") == "custom"
            else None
        )
        if manifest is None and custom_route_binding is None:
            classification = "absent"
            identity = None
            observed_hosts: list[dict[str, object]] = []
        elif manifest is None:
            raise ValueError("Caddy custom certificate binding is inconsistent")
        else:
            identity = manifest
            observed_hosts = [
                {
                    **{
                        key: value for key, value in item.items()
                        if key != "renewal_due"
                    },
                    "status": (
                        "active"
                        if item["status"] in {"active", "renewal_due"}
                        else "untrusted"
                        if item["status"] == "hostname_mismatch"
                        else item["status"]
                    ),
                }
                for item in self._probe_hosts(list(manifest["route_hosts"]), 30)
            ]
            material_dir = (
                self.certificate_dir
                / f"material-{manifest['material_id']}"
                / f"revision-{manifest['revision_id']}"
            )
            try:
                service_group_id = self._service_group_id()
                self._validate_material(
                    material_dir / "tls.crt",
                    material_dir / "tls.key",
                    list(manifest["route_hosts"]),
                    str(manifest["content_digest"]),
                    str(manifest["leaf_fingerprint_sha256"]),
                    service_group_id,
                )
            except (OSError, ValueError):
                return _unknown_custom(deployment_id)
            exact_identity = all(
                manifest[key] == requested[key]
                for key in (
                    "deployment_id", "material_id", "revision_id", "route_hosts",
                    "metadata_digest", "content_digest", "leaf_fingerprint_sha256",
                )
            )
            requested_binding = {
                "mode": "custom",
                "adapter_key": CUSTOM_ADAPTER,
                "material_id": requested["material_id"],
                "revision_id": requested["revision_id"],
            }
            serving_exact = (
                len(observed_hosts) == len(requested["route_hosts"])
                and all(
                    item["status"] == "active"
                    and item["trusted"] is True
                    and item["fingerprint_sha256"]
                    == requested["leaf_fingerprint_sha256"]
                    for item in observed_hosts
                )
            )
            manifest_binding = {
                "mode": "custom",
                "adapter_key": CUSTOM_ADAPTER,
                "material_id": manifest["material_id"],
                "revision_id": manifest["revision_id"],
            }
            serving_manifest = (
                len(observed_hosts) == len(manifest["route_hosts"])
                and all(
                    item["status"] == "active"
                    and item["trusted"] is True
                    and item["fingerprint_sha256"]
                    == manifest["leaf_fingerprint_sha256"]
                    for item in observed_hosts
                )
            )
            same_revision = (
                manifest["material_id"] == requested["material_id"]
                and manifest["revision_id"] == requested["revision_id"]
            )
            if same_revision and not exact_identity:
                classification = "unknown"
            elif exact_identity and custom_route_binding == requested_binding and serving_exact:
                classification = "exact"
            elif exact_identity:
                classification = "other"
            elif custom_route_binding == manifest_binding and serving_manifest:
                classification = "other"
            else:
                classification = "mixed"
        value = {
            "adapter_key": CUSTOM_ADAPTER,
            "mode": "custom",
            "classification": classification,
            "deployment_id": deployment_id,
            "material_id": identity["material_id"] if identity else None,
            "revision_id": identity["revision_id"] if identity else None,
            "route_hosts": identity["route_hosts"] if identity else [],
            "binding_count": 1 if identity else 0,
            "host_count": len(observed_hosts),
            "hosts": observed_hosts,
            "content_digest": identity["content_digest"] if identity else None,
            "leaf_fingerprint_sha256": (
                identity["leaf_fingerprint_sha256"] if identity else None
            ),
            "observed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        stable = {key: item for key, item in value.items() if key != "observed_at"}
        value["digest"] = hashlib.sha256(
            json.dumps(stable, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return value

    def custom_observation(
        self,
        deployment_id: str,
        organization_id: str,
        requested: dict[str, object],
    ) -> dict[str, object]:
        descriptor = self._lock()
        try:
            return self._custom_observation_locked(
                deployment_id, organization_id, requested
            )
        finally:
            self._unlock(descriptor)

    def install_custom(
        self,
        deployment_id: str,
        organization_id: str,
        requested: dict[str, object],
        expected: dict[str, object],
        source_dir: Path,
    ) -> dict[str, object]:
        files = self._validate_material(
            source_dir / "tls.crt",
            source_dir / "tls.key",
            list(requested["route_hosts"]),
            str(requested["content_digest"]),
            str(requested["leaf_fingerprint_sha256"]),
        )
        descriptor = self._lock()
        try:
            current = self._custom_observation_locked(
                deployment_id, organization_id, requested
            )
            if current.get("digest") != expected.get("digest") or current.get(
                "classification"
            ) not in {"absent", "exact", "other"}:
                raise RuntimeError("Caddy custom certificate changed before install")
            material_dir = self.certificate_dir / f"material-{requested['material_id']}"
            revision_dir = material_dir / f"revision-{requested['revision_id']}"
            manifest_path = self._manifest_path(deployment_id)
            service_group_id = self._service_group_id()
            self._prepare_directory(self.certificate_dir, service_group_id)
            self._prepare_directory(material_dir, service_group_id)
            if revision_dir.exists():
                if (
                    revision_dir.is_symlink()
                    or not revision_dir.is_dir()
                    or {entry.name for entry in revision_dir.iterdir()}
                    != {"tls.crt", "tls.key"}
                ):
                    raise RuntimeError("Immutable Caddy certificate revision conflicts")
                existing_files = self._validate_material(
                    revision_dir / "tls.crt",
                    revision_dir / "tls.key",
                    list(requested["route_hosts"]),
                    str(requested["content_digest"]),
                    str(requested["leaf_fingerprint_sha256"]),
                )
                if existing_files != files:
                    raise RuntimeError("Immutable Caddy certificate revision conflicts")
            else:
                with tempfile.TemporaryDirectory(
                    prefix=f".revision-{requested['revision_id']}.",
                    dir=str(material_dir),
                ) as temporary:
                    stage = Path(temporary)
                    for name, value in files.items():
                        target = stage / name
                        target.write_bytes(value)
                        os.chown(target, 0, service_group_id)
                        os.chmod(target, 0o640)
                    os.chown(stage, 0, service_group_id)
                    os.chmod(stage, 0o710)
                    os.rename(stage, revision_dir)
            os.chown(revision_dir, 0, service_group_id)
            os.chmod(revision_dir, 0o710)
            for name in files:
                os.chown(revision_dir / name, 0, service_group_id)
                os.chmod(revision_dir / name, 0o640)
            final_files = self._validate_material(
                revision_dir / "tls.crt",
                revision_dir / "tls.key",
                list(requested["route_hosts"]),
                str(requested["content_digest"]),
                str(requested["leaf_fingerprint_sha256"]),
                service_group_id,
            )
            if final_files != files:
                raise RuntimeError("Immutable Caddy certificate revision conflicts")
            manifest = {
                "adapter_key": CUSTOM_ADAPTER,
                **requested,
            }
            raw = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
            if not manifest_path.exists() or manifest_path.read_bytes() != raw:
                self._write_manifest(manifest_path, raw)
            installed = self._read_manifest(deployment_id)
            if installed != manifest:
                raise RuntimeError("Caddy certificate manifest activation is unverified")
            result = {
                "adapter_key": CUSTOM_ADAPTER,
                "mode": "custom",
                **requested,
                "host_count": len(requested["route_hosts"]),
            }
            result["digest"] = hashlib.sha256(
                json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
            return result
        finally:
            self._unlock(descriptor)

    def unbind_custom(
        self,
        deployment_id: str,
        organization_id: str,
        requested: dict[str, object],
        expected: dict[str, object],
    ) -> dict[str, object]:
        descriptor = self._lock()
        try:
            current = self._custom_observation_locked(
                deployment_id, organization_id, requested
            )
            if current.get("digest") != expected.get("digest") or current.get(
                "classification"
            ) not in {"exact", "other", "absent"}:
                raise RuntimeError("Caddy custom certificate changed before unbind")
            routes = self._routes(organization_id)
            route = routes.get(f"{deployment_id}.caddy")
            binding = route[0]["route_tls_binding"] if route else None
            if binding == {
                "mode": "custom",
                "adapter_key": CUSTOM_ADAPTER,
                "material_id": requested["material_id"],
                "revision_id": requested["revision_id"],
            }:
                raise RuntimeError("Caddy route still binds custom certificate")
            self._manifest_path(deployment_id).unlink(missing_ok=True)
            result = self._custom_observation_locked(
                deployment_id, organization_id, requested
            )
            if result["classification"] != "absent":
                raise RuntimeError("Caddy custom certificate remains bound")
            return result
        finally:
            self._unlock(descriptor)


def _identity() -> tuple[str, str]:
    deployment_id = canonical_uuid(os.environ["OPSCTL_DEPLOYMENT_ID"])
    organization_id = canonical_uuid(os.environ["OPSCTL_ORGANIZATION_ID"])
    canonical_uuid(os.environ["OPSCTL_SERVER_ID"])
    if (
        os.environ["OPSCTL_PROXY_ENGINE"] != "caddy"
        or not os.environ["OPSCTL_TARGET_SERVER"].strip()
    ):
        raise ValueError("Caddy route execution identity is invalid")
    return deployment_id, organization_id


def _certificate_request() -> dict[str, object]:
    value = {
        "deployment_id": canonical_uuid(os.environ["OPSCTL_DEPLOYMENT_ID"]),
        "material_id": canonical_uuid(os.environ["OPSCTL_MATERIAL_ID"]),
        "revision_id": canonical_uuid(os.environ["OPSCTL_REVISION_ID"]),
        "route_hosts": json.loads(os.environ["OPSCTL_ROUTE_HOSTS"]),
        "metadata_digest": os.environ["OPSCTL_METADATA_DIGEST"],
        "content_digest": os.environ["OPSCTL_CONTENT_DIGEST"],
        "leaf_fingerprint_sha256": os.environ["OPSCTL_LEAF_FINGERPRINT"],
    }
    if (
        not valid_hosts(value["route_hosts"])
        or any(DIGEST_PATTERN.fullmatch(value[key]) is None for key in (
            "metadata_digest", "content_digest", "leaf_fingerprint_sha256"
        ))
    ):
        raise ValueError("Caddy certificate request identity is invalid")
    return value


def _unknown_custom(deployment_id: str) -> dict[str, object]:
    value = {
        "adapter_key": CUSTOM_ADAPTER,
        "mode": "custom",
        "classification": "unknown",
        "deployment_id": deployment_id,
        "material_id": None,
        "revision_id": None,
        "route_hosts": [],
        "binding_count": 0,
        "host_count": 0,
        "hosts": [],
        "content_digest": None,
        "leaf_fingerprint_sha256": None,
        "observed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    stable = {key: item for key, item in value.items() if key != "observed_at"}
    value["digest"] = hashlib.sha256(
        json.dumps(stable, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return value


def _safe_custom_result(value: dict[str, object]) -> dict[str, object]:
    safe = {
        key: item for key, item in value.items()
        if key not in {"content_digest", "deployment_id", "host_count", "digest"}
    }
    stable = {key: item for key, item in safe.items() if key != "observed_at"}
    safe["digest"] = hashlib.sha256(
        json.dumps(stable, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return safe


def _safe_install_result(value: dict[str, object]) -> dict[str, object]:
    safe = {
        key: item for key, item in value.items()
        if key not in {"content_digest", "digest"}
    }
    safe["digest"] = hashlib.sha256(
        json.dumps(safe, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return safe


def main() -> int:
    modes = {
        "observe", "converge", "observe-automatic", "observe-custom",
        "install-custom", "unbind-custom",
    }
    if len(sys.argv) != 2 or sys.argv[1] not in modes:
        raise ValueError("Caddy route contract mode is invalid")
    mode = sys.argv[1]
    contract = CaddyRouteContract()
    if mode == "observe":
        try:
            deployment_id, organization_id = _identity()
            result = contract.observe(deployment_id, organization_id)
        except Exception:
            result = unknown_observation()
        print("TEMPLATE_OUTPUT_JSON=" + json.dumps(
            {"deployment_route_observation": result},
            sort_keys=True,
            separators=(",", ":"),
        ))
        return 0
    if mode == "observe-automatic":
        if (
            os.environ["OPSCTL_ADAPTER_KEY"] != AUTOMATIC_ADAPTER
            or os.environ["OPSCTL_CERTIFICATE_MODE"] != "automatic"
        ):
            raise ValueError("Caddy automatic certificate adapter is invalid")
        canonical_uuid(os.environ["OPSCTL_GATEWAY_ID"])
        deployment_id, organization_id = _identity()
        hosts = json.loads(os.environ["OPSCTL_ROUTE_HOSTS"])
        if not valid_hosts(hosts):
            raise ValueError("Caddy automatic certificate hosts are invalid")
        try:
            result = contract.automatic_observation(
                deployment_id,
                organization_id,
                hosts,
                int(os.environ["OPSCTL_RENEWAL_DUE_DAYS"]),
            )
        except Exception:
            unknown_hosts = [{
                "hostname": host,
                "status": "unknown",
                "trusted": None,
                "fingerprint_sha256": None,
                "not_before": None,
                "not_after": None,
                "renewal_due": None,
            } for host in hosts]
            result = {
                "adapter_key": AUTOMATIC_ADAPTER,
                "mode": "automatic",
                "route_hosts": hosts,
                "challenge_type": "http-01",
                "resolver_configured": False,
                "resolver_bound": False,
                "status": "unknown",
                "hosts": unknown_hosts,
                "observed_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            }
            result["digest"] = hashlib.sha256(
                json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
        print("TEMPLATE_OUTPUT_JSON=" + json.dumps(
            {"certificate_observation": result}, sort_keys=True, separators=(",", ":")
        ))
        return 0
    if mode in {"observe-custom", "install-custom", "unbind-custom"}:
        if (
            os.environ["OPSCTL_ADAPTER_KEY"] != CUSTOM_ADAPTER
            or os.environ["OPSCTL_CERTIFICATE_MODE"] != "custom"
        ):
            raise ValueError("Caddy custom certificate adapter is invalid")
        canonical_uuid(os.environ["OPSCTL_GATEWAY_ID"])
        deployment_id, organization_id = _identity()
        requested = _certificate_request()
        if mode == "observe-custom":
            try:
                result = contract.custom_observation(
                    deployment_id, organization_id, requested
                )
            except Exception:
                result = _unknown_custom(deployment_id)
            output_key = "custom_certificate_observation"
        else:
            expected = json.loads(os.environ["OPSCTL_EXPECTED_OBSERVATION"])
            if mode == "install-custom":
                result = contract.install_custom(
                    deployment_id,
                    organization_id,
                    requested,
                    expected,
                    Path(os.environ["OPSCTL_FILE_SECRET_DIR"]),
                )
                output_key = "custom_certificate_installation"
            else:
                result = contract.unbind_custom(
                    deployment_id, organization_id, requested, expected
                )
                output_key = "custom_certificate_observation"
        public_result = (
            _safe_install_result(result)
            if output_key == "custom_certificate_installation"
            else _safe_custom_result(result)
        )
        print("TEMPLATE_OUTPUT_JSON=" + json.dumps(
            {output_key: public_result}, sort_keys=True, separators=(",", ":")
        ))
        return 0
    deployment_id, organization_id = _identity()
    if json.loads(os.environ["OPSCTL_MIDDLEWARES"]) != []:
        raise ValueError("Caddy route middleware policy is invalid")
    result = contract.converge(
        deployment_id=deployment_id,
        organization_id=organization_id,
        execution_contract=os.environ["OPSCTL_EXECUTION_CONTRACT"],
        expected_observation=json.loads(os.environ["OPSCTL_EXPECTED_OBSERVATION"]),
        route_state=os.environ["OPSCTL_ROUTE_STATE"],
        hosts=json.loads(os.environ["OPSCTL_ROUTE_HOSTS"]),
        port=int(os.environ["OPSCTL_ROUTE_PORT"]),
        use_https=json.loads(os.environ["OPSCTL_ROUTE_HTTPS"]),
        redirect=json.loads(os.environ["OPSCTL_REDIRECT"]),
        binding=json.loads(os.environ["OPSCTL_ROUTE_TLS_BINDING"]),
    )
    print(f"CADDY_ROUTE_RESULT={result}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
