#!/usr/bin/env python3
"""Observe and converge UUID-owned Caddy Deployment routes."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.request import urlopen
from uuid import UUID


HEADER_PREFIX = b"# opsctl-managed-caddy-route-v1 "
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


def route_body(hosts: list[str], port: int, use_https: bool, redirect: bool) -> bytes:
    address = ", ".join(hosts)
    backend = f"reverse_proxy 127.0.0.1:{port}"
    if not use_https:
        value = ", ".join("http://" + host for host in hosts)
        return f"{value} {{\n  {backend}\n}}\n".encode()
    result = f"{address} {{\n  tls force_automate\n  {backend}\n}}\n"
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
    ) -> None:
        self.state_path = state_path
        self.config_path = config_path
        self.route_dir = route_dir
        self.lock_path = lock_path
        self.admin_url = admin_url

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
            digest = identity["body_sha256"]
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("Managed Caddy route identity is invalid") from exc
        if (
            set(identity) != {
                "deployment_id", "organization_id", "route_hosts", "route_port",
                "route_https", "redirect_http_to_https", "body_sha256",
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
            or body != route_body(hosts, port, use_https, redirect)
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
    ) -> bytes:
        body = route_body(hosts, port, use_https, redirect)
        identity = {
            "deployment_id": deployment_id,
            "organization_id": organization_id,
            "route_hosts": hosts,
            "route_port": port,
            "route_https": use_https,
            "redirect_http_to_https": redirect,
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

    def _write_atomic(self, target: Path, content: bytes, directory: Path) -> None:
        temporary = directory / f".{target.name}.tmp"
        temporary.write_bytes(content)
        os.chmod(temporary, 0o644)
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


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in {"observe", "converge"}:
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
    )
    print(f"CADDY_ROUTE_RESULT={result}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
