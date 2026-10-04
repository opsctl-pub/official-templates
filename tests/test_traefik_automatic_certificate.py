"""Physical helper regressions; no issuer, transport or Server stand-ins."""

import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from jinja2 import Environment, StrictUndefined
import yaml


SCRIPTS = Path(__file__).parents[1] / "catalog/ansible/scripts"
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location(
    "traefik_automatic_certificate", SCRIPTS / "traefik_automatic_certificate.py",
)
ACTOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ACTOR)


class AutomaticCertificateRetirementTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.certificates = self.root / "certificates"
        self.dynamic = self.root / "dynamic"
        self.state = self.root / "never-enrolled"
        self.certificates.mkdir(mode=0o700)
        self.dynamic.mkdir(mode=0o700)
        self.request = {
            "identity": {
                "organization_id": "11111111-1111-4111-8111-111111111111",
                "server_id": "22222222-2222-4222-8222-222222222222",
                "gateway_id": "33333333-3333-4333-8333-333333333333",
                "subject": {
                    "type": "deployment", "id": "44444444-4444-4444-8444-444444444444",
                },
                "route_hosts": ["owned.example.test"],
            },
            "operation_id": "55555555-5555-4555-8555-555555555555",
            "expected_binding": None,
        }

    def retire(self, request=None, state=None):
        return ACTOR.retire(
            self.request if request is None else request,
            self.certificates, self.dynamic, self.state if state is None else state,
        )

    def test_missing_root_is_closed_idempotent_and_does_not_enroll(self):
        unrelated = self.dynamic / "unrelated.yml"
        unrelated.write_bytes(b"unrelated-owner-bytes")
        original_observe = ACTOR.TraefikCertificateSelection.observe

        def observe_under_lock(selection, request):
            with (self.certificates / ".selection.lock").open("rb") as other:
                with self.assertRaises(BlockingIOError):
                    ACTOR.fcntl.flock(other.fileno(), ACTOR.fcntl.LOCK_EX | ACTOR.fcntl.LOCK_NB)
            return original_observe(selection, request)

        with patch.object(ACTOR, "TraefikAutomaticCertificate") as issuer, \
                patch.object(ACTOR, "retirement_records") as records, \
                patch.object(ACTOR, "remove_file") as remove, \
                patch.object(ACTOR.TraefikCertificateSelection, "observe", observe_under_lock):
            first = self.retire()
            self.assertEqual(self.retire(), first)
            issuer.assert_not_called()
            records.assert_not_called()
            remove.assert_not_called()
        receipt = first["automatic_certificate_retirement"]
        self.assertEqual(set(first), {"automatic_certificate_retirement"})
        self.assertEqual(set(receipt), {
            "identity", "operation_id", "selection_state", "renewal_enrolled", "digest",
        })
        self.assertEqual(receipt["identity"], self.request["identity"])
        self.assertEqual(receipt["operation_id"], self.request["operation_id"])
        self.assertEqual(receipt["selection_state"], "absent")
        self.assertIs(receipt["renewal_enrolled"], False)
        self.assertEqual(receipt["digest"], ACTOR.digest({
            key: value for key, value in receipt.items() if key != "digest"
        }))
        self.assertFalse(self.state.exists())
        self.assertEqual(unrelated.read_bytes(), b"unrelated-owner-bytes")
        self.assertEqual(list(self.certificates.iterdir()), [self.certificates / ".selection.lock"])

    def test_dashboard_task_emits_both_original_envelopes_in_one_final_marker(self):
        task_path = SCRIPTS.parent / "tasks/traefik_server_dashboard_retirement.yml"
        tasks = yaml.safe_load(task_path.read_text())
        block = next(task["block"] for task in tasks if "block" in task)
        emissions = [task for task in block if "ansible.builtin.debug" in task]
        self.assertEqual(len(emissions), 1)
        self.assertIs(emissions[0], block[-1])
        template = Environment(undefined=StrictUndefined)
        template.filters.update({
            "regex_replace": lambda value, pattern, replacement: re.sub(
                pattern, replacement, value,
            ),
            "from_json": json.loads,
            "to_json": json.dumps,
        })
        identity = copy.deepcopy(self.request["identity"])
        identity["subject"] = {"type": "server", "id": identity["server_id"]}
        identity["gateway_id"] = None
        for binding in (None, "opaque original selected bytes\n"):
            with self.subTest(binding_present=binding is not None):
                selection = {
                    "identity": identity, "operation_id": self.request["operation_id"],
                    "expected_binding": binding,
                }
                selection["digest"] = ACTOR.digest(selection)
                retirement = {
                    "identity": identity, "operation_id": self.request["operation_id"],
                    "selection_state": "absent", "renewal_enrolled": False,
                }
                retirement["digest"] = ACTOR.digest(retirement)
                original_selection = copy.deepcopy(selection)
                original_retirement = copy.deepcopy(retirement)
                rendered = template.from_string(
                    emissions[0]["ansible.builtin.debug"]["msg"],
                ).render(
                    dashboard_retirement_observation=selection,
                    dashboard_retirement_action={"stdout": "TEMPLATE_OUTPUT_JSON=" + json.dumps({
                        "automatic_certificate_retirement": retirement,
                    })},
                )
                marker, payload = rendered.split("=", 1)
                self.assertEqual(marker, "TEMPLATE_OUTPUT_JSON")
                output = json.loads(payload)
                self.assertEqual(set(output), {
                    "automatic_certificate_selection", "automatic_certificate_retirement",
                })
                self.assertEqual(output["automatic_certificate_selection"], original_selection)
                self.assertEqual(output["automatic_certificate_retirement"], original_retirement)
                self.assertEqual(selection, original_selection)
                self.assertEqual(retirement, original_retirement)
                for envelope in output.values():
                    self.assertEqual(envelope["digest"], ACTOR.digest({
                        key: value for key, value in envelope.items() if key != "digest"
                    }))

    def test_closed_request_and_nonnull_expected_binding_refuse_without_state(self):
        for change in ({"extra": True}, {"operation_id": "invalid"},
                       {"expected_binding": "previous-selected-bytes"}):
            request = {**copy.deepcopy(self.request), **change}
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.retire(request)
            self.assertFalse(self.state.exists())

    def test_selected_nonnull_and_unreadable_binding_refuse(self):
        with patch.object(ACTOR.TraefikCertificateSelection, "observe", return_value={
            "automatic_certificate_selection": {"expected_binding": "selected-bytes"},
        }), self.assertRaises(ACTOR.AutomaticCertificateError):
            self.retire()
        binding = self.dynamic / ("certificate-" + ACTOR.subject_key(
            self.request["identity"]["subject"],
        ) + ".yml")
        binding.write_bytes(b"foreign-unparseable-binding")
        with self.assertRaises(ACTOR.CertificateSelectionError):
            self.retire()
        self.assertEqual(binding.read_bytes(), b"foreign-unparseable-binding")
        self.assertFalse(self.state.exists())

    def test_symlink_noncanonical_and_unsafe_parent_refuse_without_traversal(self):
        self.state.symlink_to(self.root / "absent-link-target", target_is_directory=True)
        paths = (self.state, self.root / "unsafe-parent" / "child",
                 str(self.root) + "/./missing", str(self.root) + "/../missing")
        (self.root / "unsafe-parent").symlink_to(self.dynamic, target_is_directory=True)
        for path in paths:
            with self.subTest(path=str(path)), \
                    patch.object(ACTOR.TraefikCertificateSelection, "observe") as observe, \
                    self.assertRaises(ACTOR.AutomaticCertificateError):
                self.retire(state=path)
            observe.assert_not_called()
        self.assertTrue(self.state.is_symlink())
        self.assertFalse((self.dynamic / "child").exists())

    def test_permission_unknown_and_root_appearance_refuse(self):
        real_metadata = ACTOR.layout_metadata
        missing = real_metadata(str(self.state))
        unknown = {**missing, "code": "stat_unavailable", "exists": None}
        for sequence in ((unknown,), (missing, unknown), (missing, missing, unknown)):
            with self.subTest(sequence=len(sequence)), \
                    patch.object(ACTOR, "layout_metadata", side_effect=sequence), \
                    self.assertRaises(ACTOR.AutomaticCertificateError):
                self.retire()
        observed = {**missing, "code": "observed", "exists": True, "is_dir": True}
        with patch.object(ACTOR, "layout_metadata", side_effect=(missing, observed)), \
                patch.object(ACTOR.TraefikCertificateSelection, "observe") as observe, \
                self.assertRaises(ACTOR.AutomaticCertificateError):
            self.retire()
        observe.assert_not_called()
        original_observe = ACTOR.TraefikCertificateSelection.observe

        def observe_and_create(selection, request):
            observation = original_observe(selection, request)
            self.state.mkdir(mode=0o700)
            return observation

        with patch.object(ACTOR.TraefikCertificateSelection, "observe", observe_and_create), \
                self.assertRaises(ACTOR.AutomaticCertificateError):
            self.retire()
        self.assertEqual(list(self.state.iterdir()), [])

    def test_existing_root_guards_and_retirement_remain_intact(self):
        self.state.write_bytes(b"not-a-directory")
        with self.assertRaises(ACTOR.AutomaticCertificateError):
            self.retire()
        self.assertEqual(self.state.read_bytes(), b"not-a-directory")
        self.state.unlink()
        self.state.mkdir(mode=0o755)
        with self.assertRaises(ACTOR.AutomaticCertificateError):
            self.retire()
        self.state.chmod(0o700)
        receipt = self.retire()["automatic_certificate_retirement"]
        self.assertEqual(receipt["selection_state"], "absent")
        subject = self.state / ACTOR.subject_key(self.request["identity"]["subject"])
        self.assertEqual(list(subject.iterdir()), [subject / ".issuer.lock"])
        enrollment = subject / "renewal.json"
        enrollment.write_bytes(b"corrupt-enrollment")
        enrollment.chmod(0o600)
        with self.assertRaises(ValueError):
            self.retire()
        self.assertEqual(enrollment.read_bytes(), b"corrupt-enrollment")


class AutomaticCertificateCustomPredecessorTests(unittest.TestCase):
    """Real local receipts/CAS with issuer and serving boundaries doubled."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.certificates = self.root / "certificates"
        self.dynamic = self.root / "dynamic"
        self.state = self.root / "state"
        for directory in (self.certificates, self.dynamic, self.state):
            directory.mkdir(mode=0o700)
        self.identity = {
            "organization_id": "11111111-1111-4111-8111-111111111111",
            "server_id": "22222222-2222-4222-8222-222222222222",
            "gateway_id": "33333333-3333-4333-8333-333333333333",
            "subject": {"type": "deployment", "id": "44444444-4444-4444-8444-444444444444"},
            "route_hosts": ["owned.example.test"],
        }
        profile = {
            "email": "owner@example.test", "challenge": "http-01",
            "server_url": "https://acme.example.test/directory",
            "broker_url": None, "token_file": None,
        }
        self.actor = ACTOR.TraefikAutomaticCertificate(
            self.certificates, self.dynamic, self.state, profile,
        )
        revision = self.certificates / "material-66666666-6666-4666-8666-666666666666" / (
            "revision-77777777-7777-4777-8777-777777777777"
        )
        revision.mkdir(mode=0o700, parents=True)
        self.custom_cert = revision / "tls.crt"
        self.custom_key = revision / "tls.key"
        fingerprint = self.write_material(self.custom_cert, self.custom_key)
        self.custom_owner = {
            **copy.deepcopy(self.identity), "source": "custom",
            "revision_id": "77777777-7777-4777-8777-777777777777",
            "fingerprint_sha256": fingerprint,
        }
        self.binding = self.actor.selection.binding(self.custom_owner)
        self.original = self.actor.selection.document(
            self.custom_owner, self.custom_cert, self.custom_key,
        )
        self.binding.write_bytes(self.original)
        self.original_files = (self.custom_cert.read_bytes(), self.custom_key.read_bytes())
        self.request = {
            "identity": copy.deepcopy(self.identity),
            "operation_id": "55555555-5555-4555-8555-555555555555",
            "action": "issue", "expected_binding": self.original.decode("ascii"),
        }
        self.directory = self.state / ACTOR.subject_key(self.identity["subject"])
        self.receipt = self.directory / (self.request["operation_id"] + ".json")
        self.issue = self.patch_boundary("issue", side_effect=self.issue_output)
        self.verify = self.patch_boundary(
            "verify_served", side_effect=lambda owner: owner["fingerprint_sha256"],
        )
        self.patch_boundary("assert_file_serving")

    def patch_boundary(self, name, **kwargs):
        patcher = patch.object(self.actor, name, **kwargs)
        result = patcher.start()
        self.addCleanup(patcher.stop)
        return result

    def write_material(self, certificate, private_key, expired=False):
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.identity["route_hosts"][0])])
        now = datetime.now(timezone.utc)
        leaf = (
            x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=2) if expired else now - timedelta(minutes=1))
            .not_valid_after(now - timedelta(days=1) if expired else now + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName(host) for host in self.identity["route_hosts"]
            ]), critical=False).sign(key, hashes.SHA256())
        )
        certificate.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        private_key.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        certificate.chmod(0o600)
        private_key.chmod(0o600)
        return leaf.fingerprint(hashes.SHA256()).hex()

    def issue_output(self, directory, operation_id, action):
        self.assertEqual((operation_id, action), (self.request["operation_id"], "issue"))
        self.assertEqual(self.binding.read_bytes(), self.original)
        output = directory / "certificates"
        output.mkdir(mode=0o700)
        hostname = self.identity["route_hosts"][0]
        self.write_material(output / (hostname + ".crt"), output / (hostname + ".key"))

    def assert_custom_files_retained(self):
        self.assertEqual(
            (self.custom_cert.read_bytes(), self.custom_key.read_bytes()), self.original_files,
        )

    def test_original_custom_request_issues_once_and_replays_without_replacement(self):
        original_request = copy.deepcopy(self.request)
        result = self.actor.run(self.request)
        desired = self.binding.read_bytes()
        inode = self.binding.stat().st_ino
        self.assertNotEqual(desired, self.original)
        self.assertEqual(result["owner"]["source"], "automatic")
        self.assertEqual(self.actor.run(original_request), result)
        self.assertEqual(self.binding.read_bytes(), desired)
        self.assertEqual(self.binding.stat().st_ino, inode)
        self.assertEqual(self.issue.call_count, 1)
        self.assertEqual(self.verify.call_count, 2)
        self.assertEqual(self.request, original_request)
        receipt = ACTOR.private_json(self.receipt)
        self.assertEqual(receipt["status"], "active")
        self.assertEqual(receipt["request_digest"], ACTOR.digest({
            "request": original_request, "profile": self.actor.profile,
        }))
        self.assertEqual(ACTOR.private_json(self.directory / "renewal.json"),
                         self.actor._renewal_configuration())
        self.assert_custom_files_retained()

    def test_raw_or_expected_drift_refuses_before_issuer(self):
        for current, expected in ((self.original + b"\n", self.original),
                                  (self.original, self.original + b"\n")):
            with self.subTest(current_changed=current != self.original):
                self.binding.write_bytes(current)
                request = {**self.request, "expected_binding": expected.decode("ascii")}
                with self.assertRaises(ACTOR.AutomaticCertificateError):
                    self.actor.run(request)
                self.assertEqual(self.binding.read_bytes(), current)
                self.assertFalse(self.receipt.exists())
                self.issue.assert_not_called()
                self.verify.assert_not_called()

    def test_verify_failure_restores_raw_and_retries_issued_receipt_without_reissue(self):
        self.verify.side_effect = ACTOR.AutomaticCertificateError("controlled serving refusal")
        with self.assertRaises(ACTOR.AutomaticCertificateError):
            self.actor.run(self.request)
        self.assertEqual(self.binding.read_bytes(), self.original)
        self.assertEqual(ACTOR.private_json(self.receipt)["status"], "issued")
        self.assertFalse((self.directory / "renewal.json").exists())
        self.assert_custom_files_retained()
        self.verify.side_effect = lambda owner: owner["fingerprint_sha256"]
        result = self.actor.run(copy.deepcopy(self.request))
        self.assertEqual(result["status"], "active")
        self.assertEqual(self.issue.call_count, 1)
        self.assertEqual(ACTOR.private_json(self.receipt)["status"], "active")

    def test_post_issue_drift_refuses_activation_and_retains_issued_receipt(self):
        candidate = self.actor.candidate
        drifted = self.original + b"changed after issuance\n"

        def change_after_candidate(directory):
            result = candidate(directory)
            self.binding.write_bytes(drifted)
            return result

        with patch.object(self.actor, "candidate", side_effect=change_after_candidate):
            with self.assertRaises(ACTOR.CertificateSelectionError):
                self.actor.run(self.request)
        self.assertEqual(self.binding.read_bytes(), drifted)
        self.assertEqual(ACTOR.private_json(self.receipt)["status"], "issued")
        self.assertEqual(self.issue.call_count, 1)
        self.verify.assert_not_called()
        self.assert_custom_files_retained()

    def test_conflicting_selected_pool_refuses_activation_without_removing_other_owner(self):
        other_owner = {
            **copy.deepcopy(self.custom_owner),
            "subject": {"type": "deployment", "id": "88888888-8888-4888-8888-888888888888"},
        }
        other_binding = self.actor.selection.binding(other_owner)
        other_bytes = self.actor.selection.document(
            other_owner, self.custom_cert, self.custom_key,
        )
        other_binding.write_bytes(other_bytes)
        with self.assertRaises(ACTOR.CertificateSelectionError):
            self.actor.run(self.request)
        self.assertEqual(self.binding.read_bytes(), self.original)
        self.assertEqual(other_binding.read_bytes(), other_bytes)
        self.assertEqual(ACTOR.private_json(self.receipt)["status"], "issued")
        self.verify.assert_not_called()
        self.assert_custom_files_retained()

    def test_restored_custom_retirement_preserves_files_and_clears_subject_enrollment(self):
        self.actor.run(self.request)
        automatic = self.binding.read_bytes()
        self.actor.selection.activate(
            self.custom_owner, self.custom_cert, self.custom_key, automatic, lambda: None,
        )
        request = {
            "identity": self.identity, "operation_id": self.request["operation_id"],
            "expected_binding": self.original.decode("ascii"),
        }
        output = ACTOR.retire(request, self.certificates, self.dynamic, self.state)
        receipt = output["automatic_certificate_retirement"]
        self.assertEqual(receipt["selection_state"], "preserved_nonautomatic")
        self.assertIs(receipt["renewal_enrolled"], False)
        self.assertEqual(self.binding.read_bytes(), self.original)
        self.assertFalse((self.directory / "renewal.json").exists())
        self.assertFalse((self.directory / "renewal-request.json").exists())
        self.assertTrue(self.receipt.exists())
        self.assertEqual(ACTOR.retire(request, self.certificates, self.dynamic, self.state), output)
        self.assert_custom_files_retained()


class ExpiredOwnedCertificateTests(unittest.TestCase):
    """Real dated PEMs and local helper effects; issuer/TLS boundaries are doubles."""

    patch_boundary = AutomaticCertificateCustomPredecessorTests.patch_boundary
    write_material = AutomaticCertificateCustomPredecessorTests.write_material
    issue_output = AutomaticCertificateCustomPredecessorTests.issue_output

    def setUp(self):
        AutomaticCertificateCustomPredecessorTests.setUp(self)
        self.actor.identity = copy.deepcopy(self.identity)
        revision = self.certificates / ("automatic-" + ACTOR.subject_key(self.identity["subject"]))
        revision = revision / self.custom_owner["revision_id"]
        revision.mkdir(mode=0o700, parents=True)
        self.expired_cert, self.expired_key = revision / "tls.crt", revision / "tls.key"
        self.expired_owner, self.original = self.expired_selection(
            self.identity, self.expired_cert, self.expired_key,
        )
        self.binding.write_bytes(self.original)
        self.expired_files = (self.expired_cert.read_bytes(), self.expired_key.read_bytes())
        self.directory.mkdir(mode=0o700)
        self.actor.enroll(self.directory)
        self.configuration = self.actor._renewal_configuration()
        self.pending = self.directory / "renewal-request.json"
        self.issue.side_effect = self.renewal_output
        self.candidate_expired = False
        self.original_request = None
        leaf = x509.load_pem_x509_certificate(self.expired_cert.read_bytes())
        self.assertLess(leaf.not_valid_after_utc, datetime.now(timezone.utc))
        self.assertEqual(self.actor.selection.read(
            self.binding, require_current_validity=False,
        )["owner"], self.expired_owner)
        with self.assertRaises(ACTOR.CertificateSelectionError):
            self.actor.selection.read(self.binding)

    def expired_selection(self, identity, certificate, private_key):
        previous_identity = self.identity
        self.identity = identity
        try:
            fingerprint = self.write_material(certificate, private_key, expired=True)
        finally:
            self.identity = previous_identity
        owner = {**copy.deepcopy(identity), "source": "automatic",
                 "revision_id": self.custom_owner["revision_id"],
                 "fingerprint_sha256": fingerprint}
        # Construct historical bytes, then validate through the real expired-aware reader.
        body = {"tls": {"certificates": [{"certFile": str(certificate),
                                           "keyFile": str(private_key)}]}}
        raw = ("# opsctl-certificate-selection " + json.dumps(
            owner, sort_keys=True, separators=(",", ":"),
        ) + "\n" + json.dumps(body, sort_keys=True) + "\n").encode("ascii")
        return owner, raw

    def renewal_output(self, directory, operation_id, action):
        self.assertEqual(action, "renew_due")
        self.original_request = ACTOR.private_json(self.pending)
        self.assertEqual(self.original_request["operation_id"], operation_id)
        self.assertEqual(self.original_request["expected_binding"], self.original.decode("ascii"))
        output = directory / "certificates"
        output.mkdir(mode=0o700, exist_ok=True)
        hostname = self.identity["route_hosts"][0]
        self.write_material(output / (hostname + ".crt"), output / (hostname + ".key"),
                            expired=self.candidate_expired)

    def renew(self):
        return self.actor.renew_scheduled(self.directory, self.configuration)

    def neighbor(self, conflicting=False):
        identity = {**copy.deepcopy(self.identity),
                    "subject": {"type": "deployment", "id": "88888888-8888-4888-8888-888888888888"}}
        if not conflicting:
            identity["route_hosts"] = ["neighbor.example.test"]
        directory = self.certificates / "neighbor"
        directory.mkdir(mode=0o700)
        owner, raw = self.expired_selection(identity, directory / "tls.crt", directory / "tls.key")
        binding = self.actor.selection.binding(owner)
        binding.write_bytes(raw)
        return binding, raw

    def test_expired_owned_renewal_requires_valid_candidate_and_original_vars_replay(self):
        neighbor, neighbor_raw = self.neighbor()
        result = self.renew()
        self.assertEqual(result["status"], "active")
        self.assertGreater(datetime.fromisoformat(result["not_after"]), datetime.now(timezone.utc))
        desired = self.binding.read_bytes()
        inode = self.binding.stat().st_ino
        self.assertEqual(self.actor.run(copy.deepcopy(self.original_request)), result)
        self.assertEqual((self.binding.read_bytes(), self.binding.stat().st_ino), (desired, inode))
        self.assertEqual(self.issue.call_count, 1)
        self.assertFalse(self.pending.exists())
        self.assertEqual(neighbor.read_bytes(), neighbor_raw)
        self.assertEqual((self.expired_cert.read_bytes(), self.expired_key.read_bytes()), self.expired_files)

    def test_verify_failure_restores_expired_raw_and_reuses_issued_receipt(self):
        self.verify.side_effect = ACTOR.AutomaticCertificateError("controlled serving refusal")
        with self.assertRaises(ACTOR.AutomaticCertificateError):
            self.renew()
        request = ACTOR.private_json(self.pending)
        receipt_path = self.directory / (request["operation_id"] + ".json")
        receipt = ACTOR.private_json(receipt_path)
        self.assertEqual(self.binding.read_bytes(), self.original)
        self.assertEqual(receipt["status"], "issued")
        self.assertEqual(receipt["request_digest"], ACTOR.digest({
            "request": request, "profile": self.actor.profile,
        }))
        self.verify.side_effect = lambda owner: owner["fingerprint_sha256"]
        self.assertEqual(self.renew()["status"], "active")
        self.assertEqual(self.issue.call_count, 1)
        self.assertFalse(self.pending.exists())
        self.assertEqual(ACTOR.private_json(receipt_path)["status"], "active")

    def test_expired_candidate_refuses_before_activation_and_retains_retry(self):
        self.candidate_expired = True
        with self.assertRaises(ACTOR.CertificateSelectionError):
            self.renew()
        request = ACTOR.private_json(self.pending)
        self.assertFalse((self.directory / (request["operation_id"] + ".json")).exists())
        self.assertEqual(self.binding.read_bytes(), self.original)
        self.issue.assert_called_once()
        self.verify.assert_not_called()

    def test_expired_pool_conflict_preserves_neighbor_and_issued_receipt(self):
        neighbor, raw = self.neighbor(conflicting=True)
        with self.assertRaises(ACTOR.CertificateSelectionError):
            self.renew()
        request = ACTOR.private_json(self.pending)
        self.assertEqual(ACTOR.private_json(
            self.directory / (request["operation_id"] + ".json"),
        )["status"], "issued")
        self.assertEqual((self.binding.read_bytes(), neighbor.read_bytes()), (self.original, raw))
        self.verify.assert_not_called()

    def test_expired_removal_exact_owner_and_raw_preserves_unused_files_and_neighbor(self):
        neighbor, raw = self.neighbor()
        for owner, expected in (({**self.expired_owner, "source": "custom"}, self.original),
                                (self.expired_owner, self.original + b"\n")):
            with self.subTest(owner_changed=owner != self.expired_owner), \
                    self.assertRaises(ACTOR.CertificateSelectionError):
                self.actor.selection.remove(owner, expected)
            self.assertEqual(self.binding.read_bytes(), self.original)
        self.actor.selection.remove(self.expired_owner, self.original)
        self.actor.selection.remove(self.expired_owner, self.original)
        self.assertFalse(self.binding.exists())
        self.assertEqual(neighbor.read_bytes(), raw)
        self.assertEqual((self.expired_cert.read_bytes(), self.expired_key.read_bytes()), self.expired_files)
        self.assertEqual(self.renew(), {"status": "inactive"})
        self.assertFalse((self.directory / "renewal.json").exists())
        self.issue.assert_not_called()

    def test_pending_raw_drift_and_foreign_identity_refuse_before_issuer(self):
        request = {**copy.deepcopy(self.request), "action": "renew_due",
                   "expected_binding": self.original.decode("ascii") + "\n"}
        ACTOR.atomic_write(self.pending, json.dumps(request).encode())
        with self.assertRaises(ACTOR.AutomaticCertificateError):
            self.renew()
        self.pending.unlink()
        header, body = self.original.split(b"\n", 1)
        foreign = {**self.expired_owner, "organization_id": "99999999-9999-4999-8999-999999999999"}
        self.binding.write_bytes(b"# opsctl-certificate-selection " + json.dumps(foreign).encode() + b"\n" + body)
        with self.assertRaises(ACTOR.AutomaticCertificateError):
            self.renew()
        self.issue.assert_not_called()
        self.verify.assert_not_called()


if __name__ == "__main__":
    unittest.main()
