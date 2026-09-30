"""Gateway-local Lego issuance feeding the canonical file-certificate selection."""

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time
from urllib.parse import urlsplit
from uuid import UUID, NAMESPACE_URL, uuid5

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from traefik_certificate_selection import (
    CertificateSelectionError, TraefikCertificateSelection, atomic_write,
    sync_directory, validate_owner, validity,
)


LEGO_IMAGE = "goacme/lego@sha256:1944e8c36055beec47c7de6f15202b41128be75eea0ffa257f0c14d93c5155fd"
IDENTITY_FIELDS = {"organization_id", "deployment_id", "gateway_id", "server_id", "route_hosts"}
PROFILE_FIELDS = {"email", "server_url", "challenge", "broker_url", "token_file"}


class AutomaticCertificateError(CertificateSelectionError):
    """Safe engine-local action error without command output or secret material."""


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def validate_url(value, path=None):
    if not isinstance(value, str):
        raise AutomaticCertificateError("Automatic certificate endpoint is invalid")
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment
            or (path is not None and parsed.path != path)):
        raise AutomaticCertificateError("Automatic certificate endpoint is invalid")


@contextmanager
def locked(path):
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "rb") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        yield


class TraefikAutomaticCertificate:
    """Own one local account/key set; serving truth remains the selected binding."""

    def __init__(self, certificate_dir, dynamic_dir, state_dir, profile):
        self.selection = TraefikCertificateSelection(certificate_dir, dynamic_dir)
        self.state_dir = Path(state_dir)
        if (not self.state_dir.is_absolute() or self.state_dir.resolve() != self.state_dir
                or not self.state_dir.is_dir() or self.state_dir.stat().st_mode & 0o077):
            raise AutomaticCertificateError("Automatic certificate state layout is invalid")
        if not isinstance(profile, dict) or set(profile) != PROFILE_FIELDS:
            raise AutomaticCertificateError("Automatic certificate profile is invalid")
        if (not isinstance(profile["email"], str) or "@" not in profile["email"]
                or len(profile["email"]) > 254 or profile["challenge"] not in {"http-01", "dns-01"}):
            raise AutomaticCertificateError("Automatic certificate profile is invalid")
        validate_url(profile["server_url"])
        if profile["challenge"] == "dns-01":
            validate_url(profile["broker_url"], "/api/v1/dns-challenge")
            token = Path(profile["token_file"])
            if (not token.is_absolute() or token.resolve() != token or not token.is_file()
                    or token.stat().st_mode & 0o077 or not 1 <= token.stat().st_size <= 8192):
                raise AutomaticCertificateError("Automatic certificate broker credential is invalid")
        elif profile["broker_url"] is not None or profile["token_file"] is not None:
            raise AutomaticCertificateError("HTTP challenge profile cannot contain broker credentials")
        self.profile = profile
        self.http_port = int(os.environ.get("OPSCTL_ACME_HTTP_PORT", "38473"))
        if not 1024 <= self.http_port <= 65535:
            raise AutomaticCertificateError("Automatic certificate challenge listener is invalid")
        self.container_name = os.environ.get("OPSCTL_TRAEFIK_CONTAINER", "traefik")

    def assert_file_serving(self):
        """Never activate file selections beside a competing built-in ACME store."""
        result = subprocess.run(["docker", "inspect", self.container_name], check=True,
                                capture_output=True, timeout=30)
        runtime = json.loads(result.stdout)[0]
        labels = runtime.get("Config", {}).get("Labels") or {}
        command = runtime.get("Config", {}).get("Cmd") or []
        if (runtime.get("State", {}).get("Running") is not True
                or labels.get("com.opsctl.managed") != "true"
                or labels.get("com.opsctl.component") != "traefik_gateway"
                or labels.get("com.opsctl.org_id") != self.identity["organization_id"]
                or "--providers.file.directory=" + str(self.selection.dynamic_dir) not in command
                or any(str(value).lower().startswith(("--certificatesresolvers.", "--configfile"))
                       for value in command)):
            raise AutomaticCertificateError("Automatic certificates require managed file-only Traefik")

    def execute_lego(self, directory, operation_id, arguments, environment):
        """Run the maintained client; remove only this action's named container."""
        name = "opsctl-acme-" + operation_id
        self.remove_client(name, operation_id)
        command = ["docker", "run", "--rm", "--name", name, "--network", "host",
                   "--label", "com.opsctl.component=automatic_certificate",
                   "--label", "com.opsctl.org_id=" + self.identity["organization_id"],
                   "--label", "com.opsctl.deployment_id=" + self.identity["deployment_id"],
                   "--label", "com.opsctl.operation_id=" + operation_id,
                   "--volume", f"{directory}:{directory}"]
        token = self.profile["token_file"]
        if token:
            command.extend(["--volume", f"{token}:{token}:ro"])
        trust = ssl.get_default_verify_paths().cafile
        if trust is None:
            raise AutomaticCertificateError("Automatic certificate system trust store is unavailable")
        command.extend(["--volume", f"{trust}:{trust}:ro", "--env", "SSL_CERT_FILE=" + trust,
                        "--env", "LEGO_CA_CERTIFICATES=" + trust])
        for key, value in environment.items():
            command.extend(["--env", key + "=" + value])
        command.extend([LEGO_IMAGE, *arguments])
        try:
            result = subprocess.run(command, capture_output=True, timeout=600)
            if result.returncode:
                raise AutomaticCertificateError("Automatic certificate issuance failed; prior selection preserved")
        finally:
            # Timeout must not leave an ACME client holding the challenge listener.
            self.remove_client(name, operation_id)

    def remove_client(self, name, operation_id):
        """Recover/clean only the exact action's client, never a name-only conflict."""
        result = subprocess.run(["docker", "inspect", name], capture_output=True, timeout=30)
        if result.returncode:
            subprocess.run(["docker", "info"], capture_output=True, check=True, timeout=30)
            return
        labels = json.loads(result.stdout)[0].get("Config", {}).get("Labels") or {}
        expected = {"com.opsctl.component": "automatic_certificate",
                    "com.opsctl.org_id": self.identity["organization_id"],
                    "com.opsctl.deployment_id": self.identity["deployment_id"],
                    "com.opsctl.operation_id": operation_id}
        if any(labels.get(key) != value for key, value in expected.items()):
            raise AutomaticCertificateError("Automatic certificate client ownership changed")
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, check=True, timeout=30)

    @contextmanager
    def challenge(self, operation_id):
        if self.profile["challenge"] == "dns-01":
            yield
            return
        with locked(self.state_dir / ".http-challenge.lock"):
            path = self.selection.dynamic_dir / f"acme-http01-{operation_id}.yml"
            hosts = " || ".join(f"Host(`{host}`)" for host in self.identity["route_hosts"])
            name = "acme-" + operation_id
            document = {"http": {
                "routers": {name: {"rule": "(" + hosts + ") && PathPrefix(`/.well-known/acme-challenge/`)",
                    "entryPoints": ["web"], "priority": 2147482000, "service": name}},
                "services": {name: {"loadBalancer": {"servers": [
                    {"url": f"http://127.0.0.1:{self.http_port}"}]}}},
            }}
            content = json.dumps(document, sort_keys=True).encode()
            if path.is_symlink() or (path.exists() and path.read_bytes() != content):
                raise AutomaticCertificateError("Automatic certificate challenge route changed")
            atomic_write(path, content, 0o644)
            try:
                yield
            finally:
                if path.is_symlink() or not path.exists() or path.read_bytes() != content:
                    raise AutomaticCertificateError("Automatic certificate challenge cleanup ownership changed")
                path.unlink()
                sync_directory(path.parent)

    def issue(self, directory, operation_id, action):
        args = ["run", "--server", self.profile["server_url"], "--email", self.profile["email"],
                "--accept-tos", "--path", str(directory)]
        for host in self.identity["route_hosts"]:
            args.extend(["--domains", host])
        environment = {}
        if self.profile["challenge"] == "dns-01":
            args.extend(["--dns", "httpreq"])
            environment = {"HTTPREQ_ENDPOINT": self.profile["broker_url"], "HTTPREQ_USERNAME": "opsctl",
                           "HTTPREQ_PASSWORD_FILE": self.profile["token_file"], "HTTPREQ_HTTP_TIMEOUT": "120"}
        else:
            # The file provider throttles reloads for two seconds by default.
            args.extend(["--http", "--http.address", f"127.0.0.1:{self.http_port}",
                         "--http.delay", "3s"])
        if action != "issue":
            args.extend(["--reuse-key", "--no-random-sleep"])
            if action == "renew":
                args.append("--renew-force")
        with self.challenge(operation_id):
            self.execute_lego(directory, operation_id, args, environment)

    def verify_served(self, owner):
        context = self.serving_context()
        deadline = time.monotonic() + 15
        for host in owner["route_hosts"]:
            while True:
                try:
                    with socket.create_connection(("127.0.0.1", 443), timeout=2) as connection:
                        with context.wrap_socket(connection, server_hostname=host) as secured:
                            leaf = secured.getpeercert(binary_form=True)
                            if hashlib.sha256(leaf).hexdigest() != owner["fingerprint_sha256"]:
                                raise AutomaticCertificateError("Automatic certificate serving identity differs")
                    break
                except (OSError, AutomaticCertificateError):
                    if time.monotonic() >= deadline:
                        raise AutomaticCertificateError("Automatic certificate trusted serving verification failed") from None
                    time.sleep(0.2)

    def serving_context(self):
        """Automatic serving requires the gateway's system Web PKI trust store."""
        return ssl.create_default_context()

    def candidate(self, directory):
        name = self.identity["route_hosts"][0]
        certificate = directory / "certificates" / (name + ".crt")
        private_key = directory / "certificates" / (name + ".key")
        for path in (certificate, private_key):
            if path.is_symlink() or path.resolve() != path or not path.is_file():
                raise AutomaticCertificateError("Automatic certificate client output is invalid")
        leaf = x509.load_pem_x509_certificate(certificate.read_bytes())
        fingerprint = leaf.fingerprint(hashes.SHA256()).hex()
        owner = {**self.identity, "source": "automatic", "fingerprint_sha256": fingerprint,
                 "revision_id": str(uuid5(NAMESPACE_URL, "opsctl:automatic:" + fingerprint))}
        parent = self.selection.certificate_dir / ("automatic-" + self.identity["deployment_id"])
        revision = parent / owner["revision_id"]
        if parent.resolve() != parent or revision.resolve() != revision:
            raise AutomaticCertificateError("Automatic certificate revision layout is invalid")
        parent.mkdir(mode=0o700, exist_ok=True)
        revision.mkdir(mode=0o700, exist_ok=True)
        for source, filename in ((certificate, "tls.crt"), (private_key, "tls.key")):
            destination = revision / filename
            content = source.read_bytes()
            if destination.exists() and destination.read_bytes() != content:
                raise AutomaticCertificateError("Automatic certificate immutable revision changed")
            atomic_write(destination, content)
        self.selection.material(owner, revision / "tls.crt", revision / "tls.key")
        return owner, revision

    def run(self, request):
        if not isinstance(request, dict) or set(request) != {"identity", "operation_id", "action", "expected_binding"}:
            raise AutomaticCertificateError("Automatic certificate request is invalid")
        identity = request["identity"]
        if not isinstance(identity, dict) or set(identity) != IDENTITY_FIELDS:
            raise AutomaticCertificateError("Automatic certificate identity is invalid")
        self.identity = identity
        validate_owner({**identity, "source": "automatic", "revision_id": identity["deployment_id"],
                        "fingerprint_sha256": "0" * 64})
        operation_id = request["operation_id"]
        if not isinstance(operation_id, str) or str(UUID(operation_id)) != operation_id:
            raise AutomaticCertificateError("Automatic certificate operation identity is invalid")
        action = request["action"]
        if action not in {"issue", "renew", "renew_due"}:
            raise AutomaticCertificateError("Automatic certificate action is invalid")
        expected = request["expected_binding"]
        if expected is not None and (not isinstance(expected, str) or len(expected) > 65536):
            raise AutomaticCertificateError("Automatic certificate prior binding is invalid")
        expected = expected.encode("ascii") if expected is not None else None
        directory = self.state_dir / identity["deployment_id"]
        directory.mkdir(mode=0o700, exist_ok=True)
        if directory.resolve() != directory or directory.stat().st_mode & 0o077:
            raise AutomaticCertificateError("Automatic certificate owner layout is invalid")
        with locked(directory / ".issuer.lock"):
            return self._run_locked(directory, operation_id, action, request, expected)

    def _run_locked(self, directory, operation_id, action, request, expected):
        self.assert_file_serving()
        binding = self.selection.binding({**self.identity, "source": "automatic",
            "revision_id": operation_id, "fingerprint_sha256": "0" * 64})
        receipt_file = directory / (operation_id + ".json")
        if receipt_file.is_symlink() or binding.is_symlink():
            raise AutomaticCertificateError("Automatic certificate execution ownership is invalid")
        receipt = json.loads(receipt_file.read_bytes()) if receipt_file.exists() else None
        request_digest = digest({"request": request, "profile": self.profile})
        current = binding.read_bytes() if binding.exists() else None
        if receipt is not None:
            if (not isinstance(receipt, dict) or set(receipt) != {"request_digest", "owner", "status"}
                    or receipt.get("request_digest") != request_digest
                    or receipt.get("status") not in {"issued", "active"}):
                raise AutomaticCertificateError("Automatic certificate replay identity changed")
            owner = receipt["owner"]
            validate_owner(owner)
            if owner["source"] != "automatic" or any(owner[field] != self.identity[field] for field in IDENTITY_FIELDS):
                raise AutomaticCertificateError("Automatic certificate replay owner changed")
            revision = self.selection.certificate_dir / ("automatic-" + self.identity["deployment_id"]) / owner["revision_id"]
            desired = self.selection.document(owner, revision / "tls.crt", revision / "tls.key")
            if current not in (expected, desired):
                raise AutomaticCertificateError("Automatic certificate selection changed after issuance")
        else:
            if current != expected:
                raise AutomaticCertificateError("Automatic certificate selection changed before issuance")
            if action != "issue":
                if current is None:
                    raise AutomaticCertificateError("Automatic renewal requires an active automatic selection")
                previous = self.selection.read(binding, require_current_validity=False)["owner"]
                if previous["source"] != "automatic" or any(previous[field] != self.identity[field] for field in IDENTITY_FIELDS):
                    raise AutomaticCertificateError("Automatic renewal cannot change certificate ownership")
            self.issue(directory, operation_id, action)
            owner, revision = self.candidate(directory)
            receipt = {"request_digest": request_digest, "owner": owner, "status": "issued"}
            atomic_write(receipt_file, json.dumps(receipt, sort_keys=True).encode())
        self.selection.activate(owner, revision / "tls.crt", revision / "tls.key", expected,
                                lambda: self.verify_served(owner))
        receipt["status"] = "active"
        atomic_write(receipt_file, json.dumps(receipt, sort_keys=True).encode())
        leaf = x509.load_pem_x509_certificate((revision / "tls.crt").read_bytes())
        return {"operation_id": operation_id, "action": action, "owner": owner, "status": "active",
                "not_after": validity(leaf, "not_valid_after").isoformat(), "challenge_type": self.profile["challenge"]}


def main():
    os.umask(0o077)
    value = json.loads(sys.stdin.buffer.read(131073))
    if not isinstance(value, dict) or set(value) != {"profile", "request"}:
        raise AutomaticCertificateError("Automatic certificate execution input is invalid")
    action = TraefikAutomaticCertificate(os.environ["OPSCTL_CERTIFICATE_DIR"],
        os.environ["OPSCTL_DYNAMIC_DIR"], os.environ["OPSCTL_ACME_STATE_DIR"], value["profile"])
    result = action.run(value["request"])
    print("TEMPLATE_OUTPUT_JSON=" + json.dumps({"automatic_certificate": result}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except CertificateSelectionError as error:
        sys.exit(str(error))
    except Exception:
        sys.exit("Automatic certificate execution failed; selected binding must be observed")
