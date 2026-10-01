"""Read-only selected-file, local enrollment and actual served-SNI evidence."""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
from uuid import UUID

from cryptography import x509
import yaml

from traefik_automatic_certificate import IDENTITY_FIELDS, TraefikAutomaticCertificate, private_json
from traefik_certificate_selection import CertificateSelectionError, TraefikCertificateSelection, subject_key, validate_owner


def utc(value):
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def empty_hosts(hosts, status):
    return [{"hostname": host, "status": status, "trusted": None,
             "fingerprint_sha256": None, "not_before": None, "not_after": None,
             "renewal_due": None} for host in hosts]


def normalized(request, configured=False, bound=False, hosts=None):
    hosts = hosts if hosts is not None else empty_hosts(request["identity"]["route_hosts"], "unknown")
    statuses = {host["status"] for host in hosts}
    if statuses == {"unknown"}:
        status = "unknown"
    elif not configured:
        status = "not_configured"
    elif not bound:
        status = "installation_failed"
    else:
        status = next((item for item in (
            "expired", "hostname_mismatch", "installation_failed", "renewal_failed",
            "unknown", "pending", "renewal_due",
        ) if item in statuses), "active" if statuses == {"active"} else "unknown")
    value = {"adapter_key": request["adapter_key"], "mode": "automatic",
             "route_hosts": request["identity"]["route_hosts"],
             "challenge_type": request["challenge_type"], "issuer_configured": configured,
             "certificate_bound": bound, "status": status, "hosts": hosts,
             "observed_at": utc(datetime.now(timezone.utc))}
    value["digest"] = hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return value


def timer_identity():
    result = subprocess.run([
        "systemctl", "show", "opsctl-certificate-renewal.timer", "--no-pager",
        "--property=Id,LoadState,ActiveState,UnitFileState",
    ], capture_output=True, timeout=10, check=True, text=True)
    fields = dict(line.split("=", 1) for line in result.stdout.splitlines())
    if (set(fields) != {"Id", "LoadState", "ActiveState", "UnitFileState"}
            or fields["Id"] != "opsctl-certificate-renewal.timer" or fields["LoadState"] != "loaded"):
        raise CertificateSelectionError("Automatic renewal timer is unavailable")
    if (fields["ActiveState"] not in {"active", "inactive", "failed", "activating", "deactivating"}
            or fields["UnitFileState"] not in {"enabled", "disabled", "masked", "static", "enabled-runtime"}):
        raise CertificateSelectionError("Automatic renewal timer evidence is invalid")
    return fields


def probe(host, renewal_days):
    context = ssl.create_default_context()
    trusted, verify_code, leaf = None, None, None
    try:
        with socket.create_connection(("127.0.0.1", 443), timeout=5) as connection:
            with context.wrap_socket(connection, server_hostname=host) as secured:
                leaf = secured.getpeercert(binary_form=True)
        trusted = True
    except ssl.SSLCertVerificationError as error:
        trusted, verify_code = False, error.verify_code
    except (OSError, ssl.SSLError):
        pass
    if leaf is None:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection(("127.0.0.1", 443), timeout=5) as connection:
                with context.wrap_socket(connection, server_hostname=host) as secured:
                    leaf = secured.getpeercert(binary_form=True)
        except (OSError, ssl.SSLError):
            pass
    value = empty_hosts([host], "installation_failed")[0]
    if leaf is None:
        return value
    certificate = x509.load_der_x509_certificate(leaf)
    due = certificate.not_valid_after_utc <= datetime.now(timezone.utc) + timedelta(days=renewal_days)
    status = "renewal_due" if due else "active"
    if trusted is not True:
        status = "expired" if verify_code == 10 else "hostname_mismatch" if verify_code == 62 else "pending"
        trusted = False
    value.update(status=status, trusted=trusted, fingerprint_sha256=hashlib.sha256(leaf).hexdigest(),
                 not_before=utc(certificate.not_valid_before_utc), not_after=utc(certificate.not_valid_after_utc),
                 renewal_due=due)
    return value


class AutomaticCertificateObservation:
    """Observe existing owners without creating locks, files or renewal work."""

    def __init__(self, request):
        self.request = request
        self.identity = request["identity"]
        self.selection = TraefikCertificateSelection(
            os.environ["OPSCTL_CERTIFICATE_DIR"], os.environ["OPSCTL_DYNAMIC_DIR"])
        self.state_dir = Path(os.environ["OPSCTL_ACME_STATE_DIR"])
        self.files = {}

    def runtime(self):
        result = subprocess.run(["docker", "inspect", self.request["container_name"]],
                                capture_output=True, timeout=10, check=True)
        runtime = json.loads(result.stdout)[0]
        command = runtime["Config"]["Cmd"]
        labels = runtime["Config"]["Labels"]
        mounts = runtime["Mounts"]
        if (runtime["State"]["Running"] is not True or runtime["HostConfig"]["NetworkMode"] != "host"
                or labels.get("com.opsctl.managed") != "true"
                or labels.get("com.opsctl.component") != "traefik_gateway"
                or labels.get("com.opsctl.org_id") != self.identity["organization_id"]
                or not isinstance(command, list) or not all(isinstance(item, str) for item in command)
                or [item for item in command if item.lower().startswith("--providers.file.directory")]
                   != ["--providers.file.directory=" + str(self.selection.dynamic_dir)]
                or [item for item in command if item.lower().startswith("--providers.file.watch")]
                   != ["--providers.file.watch=true"]
                or any(item.lower().startswith(("--certificatesresolvers", "--configfile",
                                                 "--providers.file.filename")) for item in command)):
            raise CertificateSelectionError("Automatic observation requires exact file-only gateway")
        selected_mounts = []
        for directory in (self.selection.dynamic_dir, self.selection.certificate_dir):
            matches = [mount for mount in mounts if mount["Destination"] == str(directory)]
            if len(matches) != 1 or matches[0]["Source"] != str(directory):
                raise CertificateSelectionError("Automatic observation gateway mount differs")
            selected_mounts.append(matches[0])
        return {"command": command, "mounts": selected_mounts, "id": runtime["Id"]}

    @staticmethod
    def file_evidence(path):
        if path.is_symlink() or path.resolve() != path:
            raise CertificateSelectionError("Automatic observation file identity changed")
        if not path.exists():
            return None, None
        stat = path.stat()
        if not path.is_file() or stat.st_size > 1048576:
            raise CertificateSelectionError("Automatic observation file is invalid")
        return path.read_bytes(), (stat.st_ino, stat.st_mode, stat.st_uid, stat.st_gid, stat.st_mtime_ns)

    def remember(self, path):
        evidence = self.file_evidence(path)
        self.files[path] = evidence
        return evidence[0]

    def enrollment(self):
        root = self.state_dir
        directory = root / subject_key(self.identity["subject"])
        if not root.exists():
            self.remember(root)
            return None, None
        if (root.resolve() != root or not root.is_dir() or root.stat().st_mode & 0o077
                or (directory.exists() and (directory.resolve() != directory or not directory.is_dir()
                                            or directory.stat().st_mode & 0o077))):
            raise CertificateSelectionError("Automatic renewal layout is invalid")
        path = directory / "renewal.json"
        if self.remember(path) is None:
            return None, None
        configuration = private_json(path)
        if (not isinstance(configuration, dict) or set(configuration) != {
                "identity", "profile", "certificate_dir", "dynamic_dir", "container_name", "http_port"}
                or configuration["identity"] != self.identity
                or configuration["certificate_dir"] != str(self.selection.certificate_dir)
                or configuration["dynamic_dir"] != str(self.selection.dynamic_dir)
                or configuration["container_name"] != self.request["container_name"]
                or type(configuration["http_port"]) is not int
                or not 1024 <= configuration["http_port"] <= 65535):
            raise CertificateSelectionError("Automatic renewal enrollment differs")
        issuer = TraefikAutomaticCertificate(configuration["certificate_dir"],
            configuration["dynamic_dir"], str(root), configuration["profile"])
        if issuer.profile["challenge"] != self.request["challenge_type"]:
            raise CertificateSelectionError("Automatic renewal challenge differs")
        status_path = directory / "renewal-status.json"
        status = private_json(status_path) if self.remember(status_path) is not None else None
        return configuration, status

    def read_selection(self):
        path = self.selection.dynamic_dir / ("certificate-" + subject_key(self.identity["subject"]) + ".yml")
        raw = self.remember(path)
        if raw is None:
            return None
        selected = self.selection.read(path, require_current_validity=False)
        owner = selected["owner"]
        if any(owner[field] != self.identity[field] for field in IDENTITY_FIELDS):
            raise CertificateSelectionError("Automatic certificate selected owner differs")
        files = json.loads(raw.decode("ascii").partition("\n")[2])["tls"]["certificates"][0]
        for filename in files.values():
            self.remember(Path(filename))
        return owner

    def failure_matches(self, status, owner):
        if set(status) != {"observed_at", "status"}:
            raise CertificateSelectionError("Automatic renewal failure evidence is invalid")
        path = self.state_dir / subject_key(self.identity["subject"]) / "renewal-request.json"
        if self.remember(path) is None:
            raise CertificateSelectionError("Automatic renewal failure has no retry-owner evidence")
        pending = private_json(path)
        if (not isinstance(pending, dict) or set(pending) != {
                "identity", "operation_id", "action", "expected_binding"}
                or pending["identity"] != self.identity or pending["action"] != "renew_due"
                or not isinstance(pending["operation_id"], str)
                or str(UUID(pending["operation_id"])) != pending["operation_id"]
                or not isinstance(pending["expected_binding"], str)
                or not 1 <= len(pending["expected_binding"]) <= 65536):
            raise CertificateSelectionError("Automatic renewal retry ownership is invalid")
        binding = self.selection.binding(owner)
        return pending["expected_binding"].encode("ascii") == self.files[binding][0]

    def unchanged(self, runtime, timer):
        for path, evidence in self.files.items():
            if self.file_evidence(path) != evidence:
                raise CertificateSelectionError("Automatic certificate evidence changed during probe")
        if self.runtime() != runtime or (timer is not None and timer_identity() != timer):
            raise CertificateSelectionError("Automatic gateway evidence changed during probe")
        binding = self.selection.dynamic_dir / ("certificate-" + subject_key(self.identity["subject"]) + ".yml")
        if binding.exists():
            self.selection.read(binding, require_current_validity=False)

    def observe(self):
        runtime = self.runtime()
        key = "deployment-" + self.identity["subject"]["id"]
        raw = self.remember(self.selection.dynamic_dir / (key + ".yml"))
        document = yaml.safe_load(raw) if raw is not None else None
        router = self.request["route_router"]
        route = self.request["route_observation"]
        if (route["presence"] != "present" or route["hosts"] != self.identity["route_hosts"]
                or route["https"] is not True or not isinstance(router, dict) or router.get("tls") != {}
                or document["http"]["routers"][key] != router):
            raise CertificateSelectionError("Automatic observation requires exact file-serving HTTPS route")
        owner = self.read_selection()
        configuration, renewal_status = self.enrollment()
        bound = owner is not None and owner["source"] == "automatic"
        timer = timer_identity() if configuration is not None and bound else None
        configured = configuration is not None and bound and timer["UnitFileState"] == "enabled" and timer["ActiveState"] == "active"
        if not bound:
            self.unchanged(runtime, timer)
            return normalized(self.request, hosts=empty_hosts(self.identity["route_hosts"], "not_configured"))
        observed = [probe(host, self.request["renewal_due_days"]) for host in self.identity["route_hosts"]]
        if any(host["status"] in {"active", "renewal_due"}
               and host["fingerprint_sha256"] != owner["fingerprint_sha256"] for host in observed):
            raise CertificateSelectionError("Automatic selected certificate is not the served leaf")
        if renewal_status is not None:
            if not isinstance(renewal_status, dict) or renewal_status.get("status") not in {"active", "inactive", "renewal_failed"}:
                raise CertificateSelectionError("Automatic renewal status is invalid")
            observed_at = datetime.fromisoformat(renewal_status["observed_at"].replace("Z", "+00:00"))
            if observed_at.utcoffset() != timedelta(0) or observed_at > datetime.now(timezone.utc):
                raise CertificateSelectionError("Automatic renewal status timestamp is invalid")
            if renewal_status["status"] == "inactive" and set(renewal_status) != {"observed_at", "status"}:
                raise CertificateSelectionError("Automatic renewal inactive evidence is invalid")
            if renewal_status["status"] == "active":
                if (set(renewal_status) != {"observed_at", "operation_id", "action", "owner", "status", "not_after", "challenge_type"}
                        or renewal_status["action"] not in {"issue", "renew", "renew_due"}
                        or str(UUID(renewal_status["operation_id"])) != renewal_status["operation_id"]
                        or renewal_status["challenge_type"] not in {"http-01", "dns-01"}
                        or datetime.fromisoformat(renewal_status["not_after"].replace("Z", "+00:00")).utcoffset() != timedelta(0)):
                    raise CertificateSelectionError("Automatic renewal success evidence is invalid")
                validate_owner(renewal_status["owner"])
            if renewal_status["status"] == "renewal_failed":
                if self.failure_matches(renewal_status, owner):
                    for host in observed:
                        if host["status"] in {"active", "renewal_due"}:
                            host["status"] = "renewal_failed"
        self.unchanged(runtime, timer)
        return normalized(self.request, configured, bound, observed)


def main():
    request = json.loads(sys.argv[1])
    identity = request["identity"]
    validate_owner({**identity, "source": "automatic", "revision_id": identity["subject"]["id"],
                    "fingerprint_sha256": "0" * 64})
    if (set(request) != {"identity", "adapter_key", "challenge_type", "renewal_due_days",
                         "container_name", "route_router", "route_observation"}
            or set(identity) != IDENTITY_FIELDS or identity["subject"]["type"] != "deployment"
            or request["adapter_key"] not in {"traefik_acme_http01", "traefik_acme_dns01"}
            or request["challenge_type"] != ("dns-01" if request["adapter_key"] == "traefik_acme_dns01" else "http-01")
            or type(request["renewal_due_days"]) is not int or request["renewal_due_days"] != 30):
        raise CertificateSelectionError("Automatic certificate observation request is invalid")
    try:
        value = AutomaticCertificateObservation(request).observe()
    except (CertificateSelectionError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        value = normalized(request)
    print("TEMPLATE_OUTPUT_JSON=" + json.dumps({"certificate_observation": value}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        sys.exit("Automatic certificate observation input is invalid")
