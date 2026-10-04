"""Physical helper regressions; no issuer, transport or Server stand-ins."""

import copy
import importlib.util
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import patch

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


if __name__ == "__main__":
    unittest.main()
