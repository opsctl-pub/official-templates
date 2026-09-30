#!/usr/bin/env python3
"""Gateway-local native key custody and transactional Traefik certificate binding."""

from datetime import datetime, timezone
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from traefik_certificate_selection import (
    CertificateSelectionError, TraefikCertificateSelection, atomic_write,
)


class NativeOriginCertificate:
    """Keep keys local; an adapter supplies only signed certificates and public roots."""

    def __init__(self, certificate_dir: Path, dynamic_dir: Path, identity: dict):
        self.identity = identity
        for field in ("organization_id", "deployment_id", "gateway_id", "server_id", "revision_id"):
            if str(UUID(identity[field])) != identity[field]:
                raise ValueError("Native certificate execution identity is invalid")
        hosts = identity["route_hosts"]
        if not isinstance(hosts, list) or not 1 <= len(hosts) <= 100 or hosts != sorted(set(hosts)):
            raise ValueError("Native certificate hosts are invalid")
        for host in hosts:
            if (
                not isinstance(host, str) or host != host.lower() or len(host) > 253
                or not host.isascii() or any(
                    not label or len(label) > 63 or label[0] == "-" or label[-1] == "-"
                    or any(not (char.isalnum() or char == "-") for char in label)
                    for label in host.split(".")
                )
            ):
                raise ValueError("Native certificate hostname is invalid")
            try:
                ipaddress.ip_address(host)
            except ValueError:
                continue
            raise ValueError("Native certificate requires DNS hostnames")
        for path in (certificate_dir, dynamic_dir):
            if not path.is_absolute() or path.is_symlink() or not path.is_dir():
                raise ValueError("Native certificate layout is unavailable")
        self.base = certificate_dir / ("native-" + identity["deployment_id"])
        self.selection = TraefikCertificateSelection(certificate_dir, dynamic_dir)
        self.binding = dynamic_dir / ("certificate-" + identity["deployment_id"] + ".yml")
        if self.base.is_symlink():
            raise ValueError("Native certificate layout is invalid")
        self.base.mkdir(mode=0o700, exist_ok=True)
        self.revision = self.base / identity["revision_id"]

    def bind_identity(self):
        value = {key: self.identity[key] for key in (
            "organization_id", "deployment_id", "gateway_id", "server_id", "revision_id", "route_hosts",
        )}
        content = json.dumps(value, sort_keys=True).encode()
        path = self.revision / "identity.json"
        if path.is_symlink() or (path.exists() and path.read_bytes() != content):
            raise ValueError("Native certificate revision identity changed")
        if not path.exists():
            atomic_write(path, content)

    def lock(self):
        path = self.base / ".lock"
        descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        return os.fdopen(descriptor, "rb")

    def csr(self):
        """Replay the same local key/CSR after restart; stdout contains no key bytes."""
        with self.lock():
            if self.revision.is_symlink():
                raise ValueError("Native certificate revision is invalid")
            self.revision.mkdir(mode=0o700, exist_ok=True)
            self.bind_identity()
            key_path = self.revision / "tls.key"
            if key_path.is_symlink():
                raise ValueError("Native certificate key ownership is invalid")
            if not key_path.exists():
                key = ec.generate_private_key(ec.SECP256R1())
                atomic_write(key_path, key.private_bytes(
                    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ))
            if key_path.stat().st_mode & 0o077:
                raise ValueError("Native certificate key permissions are invalid")
            key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
            csr_path = self.revision / "csr.pem"
            if not csr_path.exists():
                csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([])).add_extension(
                    x509.SubjectAlternativeName([x509.DNSName(host) for host in self.identity["route_hosts"]]),
                    critical=False,
                ).sign(key, hashes.SHA256())
                atomic_write(csr_path, csr.public_bytes(serialization.Encoding.PEM))
            if csr_path.is_symlink():
                raise ValueError("Native certificate CSR ownership is invalid")
            csr = x509.load_pem_x509_csr(csr_path.read_bytes())
            public = key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            if (
                not csr.is_signature_valid or csr.public_key().public_bytes(
                    serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
                ) != public
                or sorted(csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                          .get_values_for_type(x509.DNSName)) != self.identity["route_hosts"]
            ):
                raise ValueError("Native certificate CSR identity changed")
            return {"revision_id": self.identity["revision_id"],
                    "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode(),
                    "public_key_spki_sha256": hashlib.sha256(public).hexdigest()}

    def binding_bytes(self, revision_id):
        if str(UUID(revision_id)) != revision_id:
            raise ValueError("Native certificate predecessor is invalid")
        path = self.base / revision_id
        leaf = x509.load_pem_x509_certificate((path / "tls.crt").read_bytes())
        return self.selection.document(
            self.selection_owner(revision_id, leaf.fingerprint(hashes.SHA256()).hex()),
            path / "tls.crt", path / "tls.key",
        )

    def selection_owner(self, revision_id, fingerprint):
        return {
            **{field: self.identity[field] for field in (
                "organization_id", "deployment_id", "gateway_id", "server_id", "route_hosts",
            )},
            "revision_id": revision_id, "source": "native", "fingerprint_sha256": fingerprint,
        }

    def verify_served(self, trust_file, fingerprint, address, port):
        """Verify SNI, hostname, trust and exact served leaf on the local gateway listener."""
        if not ipaddress.ip_address(address).is_loopback or type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("Native certificate listener identity is invalid")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cafile=str(trust_file))
        deadline = time.monotonic() + 10
        for host in self.identity["route_hosts"]:
            while True:
                try:
                    with socket.create_connection((address, port), timeout=1) as connection:
                        with context.wrap_socket(connection, server_hostname=host) as secured:
                            if hashlib.sha256(secured.getpeercert(binary_form=True)).hexdigest() != fingerprint:
                                raise ValueError("Native served certificate identity changed")
                    break
                except (OSError, ValueError):
                    if time.monotonic() >= deadline:
                        raise ValueError("Native certificate serving verification failed") from None
                    time.sleep(0.1)

    def install(self, chain_pem, trust_pem, fingerprint, trust_digest,
                previous_revision_id, address="127.0.0.1", port=443):
        """Bind validated public material, verify actual TLS, restore exact prior bytes on failure."""
        with self.lock():
            if self.revision.is_symlink() or not self.revision.is_dir():
                raise ValueError("Native certificate local key is unavailable")
            self.bind_identity()
            key_path = self.revision / "tls.key"
            if key_path.is_symlink() or key_path.stat().st_mode & 0o077:
                raise ValueError("Native certificate key ownership is invalid")
            key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
            certificates = x509.load_pem_x509_certificates(chain_pem.encode("ascii"))
            leaf = certificates[0]
            leaf_key = leaf.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            local_key = key.public_key().public_bytes(
                serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            if (
                leaf.fingerprint(hashes.SHA256()).hex() != fingerprint
                or leaf_key != local_key
                or sorted(leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                          .get_values_for_type(x509.DNSName)) != self.identity["route_hosts"]
                or hashlib.sha256(trust_pem.encode("ascii")).hexdigest() != trust_digest
            ):
                raise ValueError("Native certificate material identity changed")
            cert_path = self.revision / "tls.crt"
            trust_path = self.revision / "trust.pem"
            for path, content in ((cert_path, chain_pem), (trust_path, trust_pem)):
                if path.is_symlink() or (path.exists() and path.read_text() != content):
                    raise ValueError("Native immutable revision conflicts")
                if not path.exists():
                    atomic_write(path, content.encode("ascii"))
            # Trust anchors come from the adapter, never from the returned chain.
            for host in self.identity["route_hosts"]:
                result = subprocess.run(
                    ["openssl", "verify", "-no-CAfile", "-no-CApath", "-no-CAstore",
                     "-trusted", str(trust_path), "-untrusted", str(cert_path),
                     "-purpose", "sslserver", "-verify_hostname", host, str(cert_path)],
                    capture_output=True, timeout=5,
                )
                if result.returncode:
                    raise ValueError("Native origin chain trust is invalid")
            if self.binding.is_symlink():
                raise ValueError("Native certificate binding ownership is invalid")
            expected = self.binding_bytes(previous_revision_id) if previous_revision_id else None
            try:
                self.selection.activate(
                    self.selection_owner(self.identity["revision_id"], fingerprint),
                    cert_path, key_path, expected,
                    lambda: self.verify_served(trust_path, fingerprint, address, port),
                )
            except Exception:
                if previous_revision_id and self.binding.is_file() and self.binding.read_bytes() == expected:
                    prior = self.base / previous_revision_id
                    old_leaf = x509.load_pem_x509_certificate((prior / "tls.crt").read_bytes())
                    self.verify_served(
                        prior / "trust.pem", old_leaf.fingerprint(hashes.SHA256()).hex(), address, port,
                    )
                raise
            return {"revision_id": self.identity["revision_id"], "fingerprint_sha256": fingerprint,
                    "trust_bundle_sha256": trust_digest, "route_hosts": self.identity["route_hosts"],
                    "classification": "serving", "observed_at": datetime.now(timezone.utc).isoformat()}

    def observe(self, fingerprint, trust_digest):
        """Verify the installed revision on the final route without rewriting a file."""
        with self.lock(), self.selection.locked():
            if not (self.revision / "identity.json").is_file():
                raise ValueError("Native final revision identity is unavailable")
            self.bind_identity()
            if (
                self.binding.is_symlink() or not self.binding.is_file()
                or self.binding.read_bytes() != self.binding_bytes(self.identity["revision_id"])
                or (self.revision / "trust.pem").is_symlink()
                or hashlib.sha256((self.revision / "trust.pem").read_bytes()).hexdigest() != trust_digest
            ):
                raise ValueError("Native final certificate binding changed")
            self.verify_served(self.revision / "trust.pem", fingerprint, "127.0.0.1", 443)
            return {
                "revision_id": self.identity["revision_id"], "fingerprint_sha256": fingerprint,
                "trust_bundle_sha256": trust_digest, "route_hosts": self.identity["route_hosts"],
                "classification": "serving", "observed_at": datetime.now(timezone.utc).isoformat(),
            }

    def retire(self, active_revision_id, active_fingerprint):
        """Remove a retired local revision only while its exact replacement is serving."""
        if active_revision_id == self.identity["revision_id"]:
            raise ValueError("Native active revision cannot be retired")
        desired = self.binding_bytes(active_revision_id)
        with self.lock(), self.selection.locked():
            if self.binding.is_symlink() or not self.binding.is_file() or self.binding.read_bytes() != desired:
                raise ValueError("Native retirement replacement binding changed")
            active = self.base / active_revision_id
            if active.is_symlink():
                raise ValueError("Native active revision ownership changed")
            self.verify_served(active / "trust.pem", active_fingerprint, "127.0.0.1", 443)
            if self.revision.is_symlink():
                raise ValueError("Native retired revision ownership changed")
            if self.revision.exists():
                self.bind_identity()
                allowed = {"identity.json", "tls.key", "csr.pem", "tls.crt", "trust.pem"}
                files = list(self.revision.iterdir())
                if any(path.name not in allowed or path.is_symlink() or not path.is_file() for path in files):
                    raise ValueError("Native retired revision contains unowned files")
                for path in files:
                    if path.name != "identity.json":
                        path.unlink()
                (self.revision / "identity.json").unlink()
                self.revision.rmdir()
            return {
                "revision_id": self.identity["revision_id"], "active_revision_id": active_revision_id,
                "classification": "retired", "observed_at": datetime.now(timezone.utc).isoformat(),
            }


def main():
    request = json.loads(sys.stdin.buffer.read(524289))
    contract = NativeOriginCertificate(
        Path(os.environ["OPSCTL_CERTIFICATE_DIR"]), Path(os.environ["OPSCTL_DYNAMIC_DIR"]), request,
    )
    if sys.argv[1] == "csr":
        result = contract.csr()
    elif sys.argv[1] == "install":
        result = contract.install(
            request["certificate_chain_pem"], request["trust_bundle_pem"],
            request["leaf_fingerprint_sha256"], request["trust_bundle_sha256"],
            request["previous_revision_id"],
        )
    elif sys.argv[1] == "observe":
        result = contract.observe(request["leaf_fingerprint_sha256"], request["trust_bundle_sha256"])
    elif sys.argv[1] == "retire":
        result = contract.retire(request["active_revision_id"], request["active_fingerprint_sha256"])
    else:
        raise ValueError("Native certificate action is invalid")
    print("TEMPLATE_OUTPUT_JSON=" + json.dumps({"native_certificate": result}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except CertificateSelectionError as error:
        sys.exit(str(error))
    except Exception:
        sys.exit("Native certificate execution failed")
