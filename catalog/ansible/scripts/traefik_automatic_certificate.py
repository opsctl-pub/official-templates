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
from datetime import datetime, timezone
from urllib.parse import urlsplit
from uuid import UUID, NAMESPACE_URL, uuid4, uuid5

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from traefik_certificate_selection import (
    CertificateSelectionError, TraefikCertificateSelection, atomic_write,
    HEADER, closed_json_pairs, layout_metadata, subject_key, sync_directory,
    validate_identity, validate_owner, validity,
)


LEGO_IMAGE = "goacme/lego@sha256:1944e8c36055beec47c7de6f15202b41128be75eea0ffa257f0c14d93c5155fd"
IDENTITY_FIELDS = {"organization_id", "subject", "gateway_id", "server_id", "route_hosts"}
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
                or profile["email"] != profile["email"].strip()
                or not 3 <= len(profile["email"]) <= 320
                or profile["challenge"] not in {"http-01", "dns-01"}):
            raise AutomaticCertificateError("Automatic certificate profile is invalid")
        validate_url(profile["server_url"])
        if profile["challenge"] == "dns-01":
            validate_url(profile["broker_url"], "/api/v1/dns-challenge")
            token_file = profile["token_file"]
            if (not isinstance(token_file, str) or not token_file
                    or any(ord(character) < 32 or ord(character) == 127 for character in token_file)):
                raise AutomaticCertificateError("Automatic certificate broker credential is invalid")
            token = Path(token_file)
            if (not token.is_absolute() or str(token) != token_file
                    or token_file.startswith("//") or ".." in token.parts):
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
                   "--label", "com.opsctl.subject_type=" + self.identity["subject"]["type"],
                   "--label", "com.opsctl.subject_id=" + self.identity["subject"]["id"],
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
                    "com.opsctl.subject_type": self.identity["subject"]["type"],
                    "com.opsctl.subject_id": self.identity["subject"]["id"],
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
        if self.profile["challenge"] == "dns-01":
            token = Path(self.profile["token_file"])
            if (token.resolve() != token or not token.is_file()
                    or token.stat().st_mode & 0o077 or not 1 <= token.stat().st_size <= 8192):
                raise AutomaticCertificateError("Automatic certificate broker credential is invalid")
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
        return hashlib.sha256(leaf).hexdigest()

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
        parent = self.selection.certificate_dir / ("automatic-" + subject_key(self.identity["subject"]))
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
        validate_owner({**identity, "source": "automatic", "revision_id": identity["subject"]["id"],
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
        directory = self.state_dir / subject_key(identity["subject"])
        directory.mkdir(mode=0o700, exist_ok=True)
        if directory.resolve() != directory or directory.stat().st_mode & 0o077:
            raise AutomaticCertificateError("Automatic certificate owner layout is invalid")
        with locked(directory / ".issuer.lock"):
            result = self._run_locked(directory, operation_id, action, request, expected)
            if action != "renew_due":
                self.enroll(directory)
                status = {"observed_at": datetime.now(timezone.utc).isoformat(), **result}
                atomic_write(directory / "renewal-status.json", json.dumps(status, sort_keys=True).encode())
            return result

    def _setup_request(self, request, *, create):
        """Freeze one Server setup's original selection, never reacquire its CAS."""
        if (not isinstance(request, dict)
                or set(request) != {"identity", "operation_id", "action", "expected_binding"}
                or request["action"] != "issue" or request["expected_binding"] is not None):
            raise AutomaticCertificateError("Server certificate setup request is invalid")
        identity = request["identity"]
        if not isinstance(identity, dict) or set(identity) != IDENTITY_FIELDS:
            raise AutomaticCertificateError("Server certificate setup identity is invalid")
        validate_owner({**identity, "source": "automatic",
                        "revision_id": identity["subject"]["id"], "fingerprint_sha256": "0" * 64})
        if identity["subject"]["type"] != "server":
            raise AutomaticCertificateError("Server certificate setup requires a Server subject")
        operation_id = request["operation_id"]
        if not isinstance(operation_id, str) or str(UUID(operation_id)) != operation_id:
            raise AutomaticCertificateError("Server certificate setup operation is invalid")
        self.identity = identity
        directory = self.state_dir / subject_key(identity["subject"])
        if create:
            directory.mkdir(mode=0o700, exist_ok=True)
        if (directory.resolve() != directory or not directory.is_dir()
                or directory.stat().st_mode & 0o077 or directory.stat().st_uid != 0):
            raise AutomaticCertificateError("Server certificate setup layout is invalid")
        path = directory / ("setup-" + operation_id + ".json")
        input_digest = digest({"request": request, "profile": self.profile})
        with locked(directory / ".issuer.lock"):
            if path.exists() or path.is_symlink():
                frozen = private_json(path)
            elif create:
                observed = self.selection.observe({"identity": identity, "operation_id": operation_id})
                observed = observed["automatic_certificate_selection"]
                frozen = {
                    "request": {**request, "expected_binding": observed["expected_binding"]},
                    "selection_digest": observed["digest"], "input_digest": input_digest,
                }
                atomic_write(path, json.dumps(frozen, sort_keys=True).encode())
            else:
                raise AutomaticCertificateError("Server certificate setup snapshot is unavailable")
            if (not isinstance(frozen, dict)
                    or set(frozen) != {"request", "selection_digest", "input_digest"}
                    or frozen["input_digest"] != input_digest):
                raise AutomaticCertificateError("Server certificate setup replay identity changed")
            original = frozen["request"]
            if (not isinstance(original, dict) or set(original) != set(request)
                    or any(original[field] != request[field] for field in set(request) - {"expected_binding"})
                    or (original["expected_binding"] is not None and (
                        not isinstance(original["expected_binding"], str)
                        or not original["expected_binding"].isascii()
                        or len(original["expected_binding"]) > 65536))
                    or frozen["selection_digest"] != digest({
                        "identity": identity, "operation_id": operation_id,
                        "expected_binding": original["expected_binding"],
                    })):
                raise AutomaticCertificateError("Server certificate setup snapshot changed")
        return directory, original

    def setup(self, request):
        """Use normal issuance/activation/enrollment with the frozen root request."""
        _, original = self._setup_request(request, create=True)
        return self.run(original)

    def verify_setup(self, request):
        """Observe active selection and serving without issuance or reactivation."""
        directory, original = self._setup_request(request, create=False)
        with locked(directory / ".issuer.lock"), self.selection.locked():
            self.assert_file_serving()
            record = private_json(directory / (original["operation_id"] + ".json"))
            if (not isinstance(record, dict) or set(record) != {"request_digest", "owner", "status"}
                    or record["status"] != "active"
                    or record["request_digest"] != digest({"request": original, "profile": self.profile})):
                raise AutomaticCertificateError("Server certificate setup receipt is invalid")
            owner = record["owner"]
            validate_owner(owner)
            if (owner["source"] != "automatic"
                    or any(owner[field] != self.identity[field] for field in IDENTITY_FIELDS)):
                raise AutomaticCertificateError("Server certificate setup receipt owner changed")
            revision = self.selection.certificate_dir / ("automatic-" + subject_key(self.identity["subject"])) / owner["revision_id"]
            observed = self.selection.observe({"identity": self.identity, "operation_id": original["operation_id"]})
            expected = self.selection.document(owner, revision / "tls.crt", revision / "tls.key").decode("ascii")
            if observed["automatic_certificate_selection"]["expected_binding"] != expected:
                raise AutomaticCertificateError("Server certificate setup selection changed")
            if private_json(directory / "renewal.json") != self._renewal_configuration():
                raise AutomaticCertificateError("Server certificate renewal enrollment changed")
            for command, expected_state in (("is-enabled", "enabled"), ("is-active", "active")):
                state = subprocess.run(["systemctl", command, "opsctl-certificate-renewal.timer"],
                                       capture_output=True, timeout=30)
                if state.returncode or state.stdout.decode().strip() != expected_state:
                    raise AutomaticCertificateError("Server certificate renewal timer is unavailable")
            fingerprint = self.verify_served(owner)
            leaf = x509.load_pem_x509_certificate((revision / "tls.crt").read_bytes())
            receipt = {
                "operation_id": original["operation_id"], "action": original["action"],
                "owner": owner, "status": "active",
                "not_after": validity(leaf, "not_valid_after").isoformat(),
                "challenge_type": self.profile["challenge"],
            }
            evidence = {
                "operation_id": original["operation_id"], "identity": self.identity,
                "adapter_key": "traefik_acme_dns01" if self.profile["challenge"] == "dns-01" else "traefik_acme_http01",
                "receipt": receipt, "observed_at": datetime.now(timezone.utc).isoformat(),
                "trusted": True, "served_fingerprint_sha256": fingerprint,
            }
            return {**evidence, "digest": digest(evidence)}

    def _renewal_configuration(self):
        """Keep enrollment and read-only verification on the same exact contract."""
        return {
            "identity": self.identity, "profile": self.profile,
            "certificate_dir": str(self.selection.certificate_dir),
            "dynamic_dir": str(self.selection.dynamic_dir),
            "container_name": self.container_name, "http_port": self.http_port,
        }

    def enroll(self, directory):
        """Keep scheduler input local, private, and tied to verified activation."""
        configuration = self._renewal_configuration()
        path = directory / "renewal.json"
        previous = private_json(path) if path.exists() else None
        if previous != configuration:
            atomic_write(path, json.dumps(configuration, sort_keys=True).encode())
        remove_file(directory / "renewal-request.json")

    def renew_scheduled(self, directory, configuration):
        """A failed due check retains one request; source changes never reacquire TLS."""
        with locked(directory / ".issuer.lock"):
            if private_json(directory / "renewal.json") != configuration:
                raise AutomaticCertificateError("Automatic renewal configuration changed")
            identity = configuration["identity"]
            if not isinstance(identity, dict) or set(identity) != IDENTITY_FIELDS:
                raise AutomaticCertificateError("Automatic renewal identity is invalid")
            self.identity = identity
            owner = {**identity, "source": "automatic", "revision_id": identity["subject"]["id"],
                     "fingerprint_sha256": "0" * 64}
            binding = self.selection.binding(owner)
            pending = directory / "renewal-request.json"
            if not binding.exists() and not binding.is_symlink():
                remove_file(pending)
                remove_file(directory / "renewal.json")
                return {"status": "inactive"}
            observed = self.selection.read(binding, require_current_validity=False)["owner"]
            if observed["source"] != "automatic":
                if any(observed[field] != identity[field]
                       for field in IDENTITY_FIELDS - {"route_hosts"}):
                    raise AutomaticCertificateError("Automatic renewal selection identity changed")
                remove_file(pending)
                remove_file(directory / "renewal.json")
                return {"status": "inactive"}
            if any(observed[field] != identity[field] for field in IDENTITY_FIELDS):
                raise AutomaticCertificateError("Automatic renewal selection identity changed")
            request = private_json(pending) if pending.exists() else {
                "identity": identity, "operation_id": str(uuid4()), "action": "renew_due",
                "expected_binding": binding.read_text(encoding="ascii"),
            }
            if (not isinstance(request, dict)
                    or set(request) != {"identity", "operation_id", "action", "expected_binding"}
                    or request["identity"] != identity or request["action"] != "renew_due"
                    or not isinstance(request["operation_id"], str)
                    or str(UUID(request["operation_id"])) != request["operation_id"]
                    or not isinstance(request["expected_binding"], str)
                    or len(request["expected_binding"]) > 65536):
                raise AutomaticCertificateError("Automatic renewal retry identity is invalid")
            atomic_write(pending, json.dumps(request, sort_keys=True).encode())
            result = self._run_locked(directory, request["operation_id"], "renew_due", request,
                                      request["expected_binding"].encode("ascii"))
            remove_file(pending)
            return result

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
            revision = self.selection.certificate_dir / ("automatic-" + subject_key(self.identity["subject"])) / owner["revision_id"]
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


def private_json(path):
    """Scheduled configuration and retry evidence are never public or symlinked."""
    if (path.is_symlink() or path.resolve() != path or not path.is_file()
            or path.stat().st_mode & 0o077 or path.stat().st_size > 131072):
        raise AutomaticCertificateError("Automatic renewal record is invalid")
    return json.loads(path.read_bytes())


def remove_file(path):
    if path.is_symlink():
        raise AutomaticCertificateError("Automatic renewal record ownership changed")
    path.unlink(missing_ok=True)
    sync_directory(path.parent)


def retirement_records(directory, identity, selection, state_dir):
    """Refuse corrupt or foreign renewal input before any selected-file effect."""
    enrollment = directory / "renewal.json"
    enrolled_identity = identity
    if enrollment.exists() or enrollment.is_symlink():
        config = private_json(enrollment)
        if not isinstance(config, dict) or set(config) != {
            "identity", "profile", "certificate_dir", "dynamic_dir", "container_name", "http_port",
        }:
            raise AutomaticCertificateError("Automatic renewal configuration is invalid")
        enrolled_identity = config["identity"]
        validate_identity(enrolled_identity)
        if (any(enrolled_identity[field] != identity[field]
                for field in IDENTITY_FIELDS - {"route_hosts"})
                or config["certificate_dir"] != str(selection.certificate_dir)
                or config["dynamic_dir"] != str(selection.dynamic_dir)
                or not isinstance(config["container_name"], str) or not config["container_name"]
                or type(config["http_port"]) is not int or not 1024 <= config["http_port"] <= 65535):
            raise AutomaticCertificateError("Automatic renewal configuration changed")
        TraefikAutomaticCertificate(selection.certificate_dir, selection.dynamic_dir,
                                    state_dir, config["profile"])
    pending = directory / "renewal-request.json"
    if not pending.exists() and not pending.is_symlink():
        return
    request = private_json(pending)
    if (not isinstance(request, dict)
            or set(request) != {"identity", "operation_id", "action", "expected_binding"}
            or request["identity"] != enrolled_identity or request["action"] != "renew_due"
            or not isinstance(request["operation_id"], str)
            or str(UUID(request["operation_id"])) != request["operation_id"]
            or not isinstance(request["expected_binding"], str)
            or not 1 <= len(request["expected_binding"]) <= 65536
            or not request["expected_binding"].isascii()):
        raise AutomaticCertificateError("Automatic renewal retry identity is invalid")
    header, separator, body = request["expected_binding"].partition("\n")
    if not separator or not header.startswith(HEADER):
        raise AutomaticCertificateError("Automatic renewal retry selection is invalid")
    owner = json.loads(header[len(HEADER):], object_pairs_hook=closed_json_pairs)
    validate_owner(owner)
    if (owner["source"] != "automatic"
            or any(owner[field] != enrolled_identity[field] for field in IDENTITY_FIELDS)):
        raise AutomaticCertificateError("Automatic renewal retry ownership changed")
    document = json.loads(body, object_pairs_hook=closed_json_pairs)
    if (not isinstance(document, dict) or set(document) != {"tls"}
            or not isinstance(document["tls"], dict) or set(document["tls"]) != {"certificates"}
            or not isinstance(document["tls"]["certificates"], list)
            or len(document["tls"]["certificates"]) != 1):
        raise AutomaticCertificateError("Automatic renewal retry selection is invalid")
    files = document["tls"]["certificates"][0]
    if not isinstance(files, dict) or set(files) != {"certFile", "keyFile"}:
        raise AutomaticCertificateError("Automatic renewal retry selection is invalid")
    selection.material(owner, files["certFile"], files["keyFile"], require_current_validity=False)


def retire_missing_root(request, selection, state_dir):
    """A never-enrolled subject can retire only a freshly absent selection."""
    if request["expected_binding"] is not None:
        raise AutomaticCertificateError("Automatic retirement selection changed")
    observation = {key: request[key] for key in ("identity", "operation_id")}
    with selection.locked():
        before = layout_metadata(os.fspath(state_dir))
        if (before["code"] != "missing" or before["exists"] is not False
                or before["canonical_path"] is not True):
            raise AutomaticCertificateError("Automatic retirement state layout changed")
        current = selection.observe(observation)["automatic_certificate_selection"]
        if current["expected_binding"] is not None:
            raise AutomaticCertificateError("Automatic retirement selection changed")
        after = layout_metadata(os.fspath(state_dir))
        if (after["code"] != "missing" or after["exists"] is not False
                or after["canonical_path"] is not True):
            raise AutomaticCertificateError("Automatic retirement state layout changed")
        result = {**observation, "selection_state": "absent", "renewal_enrolled": False}
        return {"automatic_certificate_retirement": {**result, "digest": digest(result)}}


def retire(request, certificate_dir, dynamic_dir, state_dir):
    """Retire only exact automatic selection and qualified renewal inputs."""
    if not isinstance(request, dict) or set(request) != {"identity", "operation_id", "expected_binding"}:
        raise AutomaticCertificateError("Automatic retirement request is invalid")
    identity = request["identity"]
    validate_identity(identity)
    operation = request["operation_id"]
    expected = request["expected_binding"]
    if (not isinstance(operation, str) or str(UUID(operation)) != operation
            or expected is not None and (not isinstance(expected, str)
                or not expected.isascii() or not 1 <= len(expected) <= 65536)):
        raise AutomaticCertificateError("Automatic retirement identity is invalid")
    root = Path(state_dir)
    layout = layout_metadata(os.fspath(state_dir))
    if (layout["code"] == "missing" and layout["exists"] is False
            and layout["canonical_path"] is True):
        return retire_missing_root(
            request, TraefikCertificateSelection(certificate_dir, dynamic_dir), state_dir,
        )
    if layout["code"] != "observed" or layout["canonical_path"] is not True:
        raise AutomaticCertificateError("Automatic retirement state layout is invalid")
    if (not root.is_absolute() or root.resolve() != root or not root.is_dir()
            or root.stat().st_mode & 0o077):
        raise AutomaticCertificateError("Automatic retirement state layout is invalid")
    selection = TraefikCertificateSelection(certificate_dir, dynamic_dir)
    directory = root / subject_key(identity["subject"])
    directory.mkdir(mode=0o700, exist_ok=True)
    if directory.resolve() != directory or directory.stat().st_mode & 0o077:
        raise AutomaticCertificateError("Automatic retirement owner layout is invalid")
    observation = {"identity": identity, "operation_id": operation}
    with locked(directory / ".issuer.lock"):
        retirement_records(directory, identity, selection, root)
        current = selection.observe(observation)["automatic_certificate_selection"]["expected_binding"]
        state = "absent"
        if current is not None:
            if current != expected:
                raise AutomaticCertificateError("Automatic retirement selection changed")
            binding = selection.dynamic_dir / ("certificate-" + subject_key(identity["subject"]) + ".yml")
            owner = selection.read(binding, require_current_validity=False)["owner"]
            if (binding.read_bytes().decode("ascii") != current
                    or any(owner[field] != identity[field]
                           for field in IDENTITY_FIELDS - {"route_hosts"})):
                raise AutomaticCertificateError("Automatic retirement selection changed")
            if owner["source"] == "automatic":
                if any(owner[field] != identity[field] for field in IDENTITY_FIELDS):
                    raise AutomaticCertificateError("Automatic retirement selection identity changed")
                selection.remove(owner, current.encode("ascii"))
            else:
                state = "preserved_nonautomatic"
        remove_file(directory / "renewal-request.json")
        remove_file(directory / "renewal.json")
        fresh = selection.observe(observation)["automatic_certificate_selection"]["expected_binding"]
        if (fresh != (current if state == "preserved_nonautomatic" else None)
                or any((directory / name).exists() or (directory / name).is_symlink()
                       for name in ("renewal.json", "renewal-request.json"))):
            raise AutomaticCertificateError("Automatic retirement verification failed")
        result = {"identity": identity, "operation_id": operation,
                  "selection_state": state, "renewal_enrolled": False}
        return {"automatic_certificate_retirement": {**result, "digest": digest(result)}}


def renew_all(state_dir, issuer_type=TraefikAutomaticCertificate):
    """One local timer, isolated per-owner attempts, and sanitized durable outcomes."""
    root = Path(state_dir)
    if (not root.is_absolute() or root.resolve() != root or not root.is_dir()
            or root.stat().st_mode & 0o077):
        raise AutomaticCertificateError("Automatic renewal state layout is invalid")
    failed = False
    for directory in sorted(root.iterdir()):
        try:
            kind, _, identifier = directory.name.partition("-")
            if kind not in {"deployment", "server"} or str(UUID(identifier)) != identifier:
                continue
        except ValueError:
            continue
        status = {"observed_at": datetime.now(timezone.utc).isoformat(),
                  "status": "renewal_failed"}
        try:
            if (directory.is_symlink() or not directory.is_dir()
                    or directory.stat().st_mode & 0o077):
                raise AutomaticCertificateError("Automatic renewal owner layout is invalid")
            path = directory / "renewal.json"
            if not path.exists() and not path.is_symlink():
                continue
            configuration = private_json(path)
            if (not isinstance(configuration, dict) or set(configuration) != {
                    "identity", "profile", "certificate_dir", "dynamic_dir", "container_name", "http_port"}
                    or not isinstance(configuration["identity"], dict)
                    or subject_key(configuration["identity"].get("subject")) != directory.name
                    or not isinstance(configuration["container_name"], str)
                    or not configuration["container_name"]
                    or type(configuration["http_port"]) is not int
                    or not 1024 <= configuration["http_port"] <= 65535):
                raise AutomaticCertificateError("Automatic renewal configuration is invalid")
            issuer = issuer_type(configuration["certificate_dir"], configuration["dynamic_dir"],
                                 root, configuration["profile"])
            issuer.container_name = configuration["container_name"]
            issuer.http_port = configuration["http_port"]
            status.update(issuer.renew_scheduled(directory, configuration))
        except Exception:
            failed = True
        # Never follow an invalid owner directory to record its failure.
        try:
            if (not directory.is_symlink() and directory.is_dir()
                    and directory.resolve() == directory and not directory.stat().st_mode & 0o077):
                atomic_write(directory / "renewal-status.json", json.dumps(status, sort_keys=True).encode())
        except OSError:
            status = {"observed_at": status["observed_at"], "status": "renewal_failed"}
            failed = True
        print(json.dumps({"subject": {"type": kind, "id": identifier}, **status}, sort_keys=True), flush=True)
    return not failed


def main():
    os.umask(0o077)
    if sys.argv[1:] == ["retire"]:
        request = json.loads(sys.stdin.buffer.read(131073), object_pairs_hook=closed_json_pairs)
        result = retire(request, os.environ["OPSCTL_CERTIFICATE_DIR"],
                        os.environ["OPSCTL_DYNAMIC_DIR"], os.environ["OPSCTL_ACME_STATE_DIR"])
        print("TEMPLATE_OUTPUT_JSON=" + json.dumps(result, sort_keys=True))
        return
    if sys.argv[1:] == ["renew-due"]:
        if not renew_all(os.environ["OPSCTL_ACME_STATE_DIR"]):
            raise AutomaticCertificateError("Automatic renewal failed; prior selection preserved")
        return
    if sys.argv[1:] not in ([], ["setup"], ["verify-setup"]):
        raise AutomaticCertificateError("Automatic certificate action is invalid")
    value = json.loads(sys.stdin.buffer.read(131073))
    if not isinstance(value, dict) or set(value) != {"profile", "request"}:
        raise AutomaticCertificateError("Automatic certificate execution input is invalid")
    action = TraefikAutomaticCertificate(os.environ["OPSCTL_CERTIFICATE_DIR"],
        os.environ["OPSCTL_DYNAMIC_DIR"], os.environ["OPSCTL_ACME_STATE_DIR"], value["profile"])
    if sys.argv[1:] == ["verify-setup"]:
        result = action.verify_setup(value["request"])
        print("TEMPLATE_OUTPUT_JSON=" + json.dumps({"server_dashboard_certificate": result}, sort_keys=True))
        return
    result = action.setup(value["request"]) if sys.argv[1:] == ["setup"] else action.run(value["request"])
    print("TEMPLATE_OUTPUT_JSON=" + json.dumps({"automatic_certificate": result}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except CertificateSelectionError as error:
        sys.exit(str(error))
    except Exception:
        sys.exit("Automatic certificate execution failed; selected binding must be observed")
