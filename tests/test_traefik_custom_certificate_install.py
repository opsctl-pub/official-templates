"""Installer task predicates and local CAS; no transport or serving stand-in."""

import copy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest.mock import Mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from jinja2 import Environment, StrictUndefined, UndefinedError
import yaml


ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "catalog/ansible/scripts"))
from traefik_certificate_selection import (  # noqa: E402
    CertificateSelectionError,
    TraefikCertificateSelection,
)


def task_named(tasks, name):
    """Find an actual task without duplicating its predicates in the test."""
    for task in tasks:
        if task.get("name") == name:
            return task
        if "block" in task:
            try:
                return task_named(task["block"], name)
            except KeyError:
                pass
    raise KeyError(name)


class CustomCertificateInstallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.play = yaml.safe_load((ROOT / "catalog/ansible/playbooks"
                                  / "traefik_custom_certificate_install.yml").read_text())[0]
        cls.environment = Environment(undefined=StrictUndefined)
        cls.environment.tests["match"] = lambda value, pattern: re.match(pattern, value) is not None
        cls.environment.filters.update({
            "bool": bool,
            "regex_replace": lambda value, pattern, replacement: re.sub(pattern, replacement, value),
            "from_json": json.loads,
            "dict2items": lambda value: [{"key": k, "value": v} for k, v in value.items()],
            "items2dict": lambda value: {item["key"]: item["value"] for item in value},
        })

    def setUp(self):
        self.context = {
            "adapter_key": "traefik_custom_file", "certificate_mode": "custom",
            "simulate": False, "org_id": "11111111-1111-4111-8111-111111111111",
            "deployment_id": "22222222-2222-4222-8222-222222222222",
            "gateway_id": "33333333-3333-4333-8333-333333333333",
            "server_id": "44444444-4444-4444-8444-444444444444",
            "material_id": "55555555-5555-4555-8555-555555555555",
            "revision_id": "66666666-6666-4666-8666-666666666666",
            "metadata_digest": "a" * 64, "content_digest": "b" * 64,
            "leaf_fingerprint_sha256": "c" * 64,
            "route_hosts": ["first.example.test", "second.example.test"],
            "target_server": "managed-target",
        }
        self.expected = {
            "identity": {
                "organization_id": self.context["org_id"],
                "subject": {"type": "deployment", "id": self.context["deployment_id"]},
                "gateway_id": self.context["gateway_id"],
                "server_id": self.context["server_id"],
                "route_hosts": list(self.context["route_hosts"]),
            },
            "operation_id": "77777777-7777-4777-8777-777777777777",
            "expected_binding": "original canonical automatic binding\n",
            "digest": "d" * 64,
        }

    def task(self, name):
        return task_named(self.play["tasks"], name)

    def evaluate(self, expression, context):
        expression = expression.strip()
        if expression.startswith("{{") and expression.endswith("}}"):
            expression = expression[2:-2].strip()
        return self.environment.compile_expression(expression, undefined_to_none=False)(**context)

    def assertions_pass(self, task, context):
        try:
            return all(self.evaluate(value, context)
                       for value in task["ansible.builtin.assert"]["that"])
        except (UndefinedError, TypeError, ValueError, AttributeError):
            return False

    def automatic_context(self, expected=...):
        selection = copy.deepcopy(self.expected if expected is ... else expected)
        return {**copy.deepcopy(self.context), "expected_automatic_certificate_selection": selection,
                "custom_predecessor_selection": selection}

    def previous_context(self, expected=...):
        selection = copy.deepcopy(self.expected if expected is ... else expected)
        if expected is ...:
            selection["identity"]["route_hosts"] = [self.context["route_hosts"][0]]
        return {**copy.deepcopy(self.context), "expected_previous_custom_selection": selection,
                "custom_predecessor_selection": selection}

    def observation(self):
        return {
            "classification": "exact", "material_id": self.context["material_id"],
            "revision_id": self.context["revision_id"],
            "content_digest": self.context["content_digest"],
            "leaf_fingerprint_sha256": self.context["leaf_fingerprint_sha256"],
            "route_hosts": list(self.context["route_hosts"]),
            "binding_count": 1, "host_count": 2,
            "hosts": [{"hostname": host, "status": "active", "trusted": True,
                       "fingerprint_sha256": self.context["leaf_fingerprint_sha256"]}
                      for host in self.context["route_hosts"]],
            "observed_at": "2026-01-01T00:00:00Z", "digest": "e" * 64,
        }

    def test_predecessor_arguments_are_exclusive(self):
        task = self.play["pre_tasks"][0]
        for automatic, custom, accepted in ((False, False, False), (True, True, False),
                                            (True, False, True), (False, True, True)):
            with self.subTest(automatic=automatic, custom=custom):
                context = copy.deepcopy(self.context)
                if automatic:
                    context["expected_automatic_certificate_selection"] = self.expected
                if custom:
                    context["expected_custom_certificate_observation"] = self.observation()
                self.assertEqual(self.assertions_pass(task, context), accepted)
        context = {**self.context, "expected_custom_certificate_observation": "not a mapping"}
        self.assertFalse(self.assertions_pass(task, context))

    def test_closed_automatic_envelope_identity_and_bounds(self):
        task = self.task("Validate the closed automatic predecessor envelope")
        self.assertTrue(self.assertions_pass(task, self.automatic_context()))
        bad = [None, [], {**self.expected, "extra": True}]
        for field in self.expected:
            value = copy.deepcopy(self.expected)
            del value[field]
            bad.append(value)
        for field, values in {
            "operation_id": [True, "invalid"],
            "expected_binding": [None, "", "x" * 65537],
            "digest": [True, "D" * 64, "d" * 63],
        }.items():
            bad.extend({**copy.deepcopy(self.expected), field: value} for value in values)
        for field in self.expected["identity"]:
            value = copy.deepcopy(self.expected)
            value["identity"][field] = None
            bad.append(value)
        for value in bad:
            with self.subTest(value=value):
                self.assertFalse(self.assertions_pass(task, self.automatic_context(value)))
        for size in (1, 65536):
            value = {**self.expected, "expected_binding": "x" * size}
            self.assertTrue(self.assertions_pass(task, self.automatic_context(value)))

    def test_complete_fresh_envelope_equality_and_exact_byte_capture(self):
        compare = self.task("Compare the complete registered predecessor envelope")
        capture = self.task("Capture the freshly qualified predecessor bytes for activation CAS")
        expression = compare["ansible.builtin.set_fact"]["custom_predecessor_unchanged"]
        original = copy.deepcopy(self.expected)
        context = self.automatic_context()
        context["certificate_selection_result"] = {
            "stdout": "TEMPLATE_OUTPUT_JSON=" + json.dumps({"automatic_certificate_selection": original})}
        self.assertTrue(self.evaluate(expression, context))
        self.assertEqual(self.evaluate(capture["ansible.builtin.set_fact"]
                                       ["custom_selected_binding_bytes"], context), original["expected_binding"])
        changed = []
        for field in original:
            value = copy.deepcopy(original)
            value[field] = {} if field == "identity" else "changed"
            changed.append({"automatic_certificate_selection": value})
        changed.extend(({}, {"automatic_certificate_selection": original, "extra": True}))
        for output in changed:
            with self.subTest(output=output):
                context["certificate_selection_result"]["stdout"] = "TEMPLATE_OUTPUT_JSON=" + json.dumps(output)
                self.assertFalse(self.evaluate(expression, context))
        self.assertEqual(self.expected, original)
        bounded = self.task("Require a bounded canonical predecessor observation")
        for stdout in ("wrong-prefix", "TEMPLATE_OUTPUT_JSON=" + "x" * 131072):
            self.assertFalse(self.assertions_pass(bounded, {
                **context, "certificate_selection_result": {"stdout": stdout}}))

    def test_requested_only_replay_refuses_identity_and_all_host_drift(self):
        task = self.task("Require exact requested custom serving for original-request replay")
        context = {**self.automatic_context(), "binding_valid": True, "binding_present": True,
                   "custom_certificate_observation": self.observation()}
        original = copy.deepcopy(context["expected_automatic_certificate_selection"])
        self.assertTrue(self.assertions_pass(task, context))
        bad = []
        for field in ("material_id", "revision_id", "content_digest", "leaf_fingerprint_sha256"):
            bad.append({**self.observation(), field: "different"})
        for classification in ("absent", "other", "mixed", "unknown"):
            bad.append({**self.observation(), "classification": classification})
        for field, value in (("route_hosts", list(reversed(self.context["route_hosts"]))),
                             ("binding_count", 0), ("binding_count", 2), ("host_count", 1)):
            bad.append({**self.observation(), field: value})
        bad.append({**self.observation(), "hosts": list(reversed(self.observation()["hosts"]))})
        bad.append({**self.observation(), "hosts": self.observation()["hosts"][:1]})
        for index in (0, 1):
            for field, value in (("hostname", "foreign.example.test"), ("status", "expired"),
                                 ("status", "unknown"), ("trusted", False), ("trusted", None),
                                 ("trusted", "true"), ("fingerprint_sha256", "f" * 64)):
                obs = self.observation()
                obs["hosts"][index][field] = value
                bad.append(obs)
        for obs in bad:
            with self.subTest(observation=obs):
                self.assertFalse(self.assertions_pass(task, {
                    **context, "custom_certificate_observation": obs}))
        for flag in ("binding_valid", "binding_present"):
            self.assertFalse(self.assertions_pass(task, {**context, flag: False}))
        self.assertEqual(context["expected_automatic_certificate_selection"], original)

    def test_ordinary_custom_physical_equality_and_replay_remain_separate(self):
        read = self.task("Read current custom certificate observation")
        guard = self.task("Require unchanged custom certificate observation")
        expected = self.observation()
        current = {**copy.deepcopy(expected), "observed_at": "2026-01-02T00:00:00Z",
                   "digest": "f" * 64, "classification": "other"}
        context = {**self.context, "expected_custom_certificate_observation": expected,
                   "custom_certificate_observation": current,
                   "binding_valid": False, "binding_present": False}
        self.assertTrue(self.evaluate(read["when"], context))
        self.assertTrue(self.assertions_pass(guard, context))
        for field in ("material_id", "revision_id", "content_digest", "leaf_fingerprint_sha256"):
            self.assertFalse(self.assertions_pass(guard, {
                **context, "custom_certificate_observation": {**current, field: "drift"}}))
        for classification in ("unknown", "mixed"):
            self.assertFalse(self.assertions_pass(guard, {
                **context, "custom_certificate_observation": {**current, "classification": classification}}))
        context.update(binding_valid=True, binding_present=True)
        context["expected_custom_certificate_observation"] = {**expected, "material_id": "old"}
        self.assertTrue(self.assertions_pass(guard, context))
        for task in (read, guard):
            self.assertFalse(self.evaluate(task["when"], self.automatic_context()))
        activation = self.task("Activate through the shared selected-pool owner")
        self.assertNotIn("when", activation)
        self.assertEqual(activation["vars"]["certificate_selection_request"]["expected_binding"],
                         "{{ custom_selected_binding_bytes }}")
        replay = self.task("Observe only an already-requested custom replay")
        self.assertEqual(replay["ansible.builtin.include_tasks"]["file"],
                         "../tasks/traefik_custom_certificate_observation.yml")
        self.assertEqual(replay["when"], "not custom_predecessor_unchanged")

    def test_shared_activation_refuses_raw_byte_drift_and_retains_desired_replay(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            certificates = root / "certificates"
            dynamic = root / "dynamic"
            certificates.mkdir(mode=0o700)
            dynamic.mkdir(mode=0o700)
            selection = TraefikCertificateSelection(certificates, dynamic)
            key = ec.generate_private_key(ec.SECP256R1())
            now = datetime.now(timezone.utc)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.context["route_hosts"][0])])
            leaf = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                    .public_key(key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
                    .add_extension(x509.SubjectAlternativeName(
                        [x509.DNSName(host) for host in self.context["route_hosts"]]), critical=False)
                    .sign(key, hashes.SHA256()))
            cert_file = certificates / "tls.crt"
            key_file = certificates / "tls.key"
            cert_file.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
            key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                  serialization.PrivateFormat.PKCS8,
                                                  serialization.NoEncryption()))
            cert_file.chmod(0o600)
            key_file.chmod(0o600)
            owner = {**copy.deepcopy(self.expected["identity"]), "source": "custom",
                     "revision_id": self.context["revision_id"],
                     "fingerprint_sha256": leaf.fingerprint(hashes.SHA256()).hex()}
            path = selection.binding(owner)
            original = self.expected["expected_binding"].encode()
            path.write_bytes(original)
            captured = path.read_bytes()
            drifted = captured + b"changed after observation\n"
            path.write_bytes(drifted)
            verify = Mock()
            with self.assertRaises(CertificateSelectionError):
                selection.activate(owner, cert_file, key_file, captured, verify)
            self.assertEqual(path.read_bytes(), drifted)
            verify.assert_not_called()
            path.write_bytes(original)
            selection.activate(owner, cert_file, key_file, captured, verify)
            desired = path.read_bytes()
            selected_identity = path.stat().st_ino
            selection.activate(owner, cert_file, key_file, captured, verify)
            self.assertEqual(path.read_bytes(), desired)
            self.assertEqual(path.stat().st_ino, selected_identity)
            self.assertEqual(verify.call_count, 2)
            selected = selection.observe({"identity": self.expected["identity"],
                                          "operation_id": self.expected["operation_id"]})
            self.assertEqual(selected["automatic_certificate_selection"]["expected_binding"],
                             desired.decode("ascii"))

    def test_all_three_predecessor_sources_are_exclusive_and_route_to_shared_cas(self):
        keys = ("expected_custom_certificate_observation", "expected_automatic_certificate_selection",
                "expected_previous_custom_selection")
        for mask in range(8):
            context = copy.deepcopy(self.context)
            for index, key in enumerate(keys):
                if mask & (1 << index):
                    context[key] = self.observation() if index == 0 else self.expected
            self.assertEqual(self.assertions_pass(self.play["pre_tasks"][0], context),
                             mask in (1, 2, 4))
        select = self.task("Select the distinct registered predecessor envelope")
        expression = select["ansible.builtin.set_fact"]["custom_predecessor_selection"]
        for context in (self.automatic_context(), self.previous_context()):
            self.assertEqual(self.evaluate(expression, context), context["custom_predecessor_selection"])
            for name in ("Read current custom certificate observation", "Require unchanged custom certificate observation"):
                self.assertFalse(self.evaluate(self.task(name)["when"], context))
        read = self.task("Read the canonical predecessor through the selected-pool owner")
        self.assertEqual(read["vars"]["certificate_selection_action"], "observe")
        self.assertEqual(read["vars"]["certificate_selection_request"], {
            "identity": "{{ custom_predecessor_selection.identity }}",
            "operation_id": "{{ custom_predecessor_selection.operation_id }}",
        })

    def test_previous_custom_envelope_preserves_prior_hosts_and_refuses_malformed_or_foreign(self):
        task = self.task("Validate the closed previous custom envelope")
        original = self.previous_context()["expected_previous_custom_selection"]
        self.assertNotEqual(original["identity"]["route_hosts"], self.context["route_hosts"])
        self.assertTrue(self.assertions_pass(task, self.previous_context(original)))
        bad = [None, [], {**original, "extra": True}]
        for field in original:
            value = copy.deepcopy(original)
            del value[field]
            bad.append(value)
        for field, values in {
            "operation_id": [None, True, "invalid"], "digest": [None, True, "D" * 64],
            "expected_binding": [None, "", "x" * 65537],
        }.items():
            bad.extend({**copy.deepcopy(original), field: value} for value in values)
        for field in original["identity"]:
            value = copy.deepcopy(original)
            value["identity"][field] = "foreign"
            bad.append(value)
        for hosts in ([], "owned.example.test", None, ["UPPER.example.test"], ["invalid host"],
                      ["first.example.test", "first.example.test"], list(reversed(self.context["route_hosts"])),
                      ["first.example.test"] * 101):
            value = copy.deepcopy(original)
            value["identity"]["route_hosts"] = hosts
            bad.append(value)
        value = copy.deepcopy(original)
        value["identity"]["extra"] = True
        bad.append(value)
        for value in bad:
            with self.subTest(value=value):
                self.assertFalse(self.assertions_pass(task, self.previous_context(value)))

    def domain_material(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        certificates, dynamic = root / "certificates", root / "dynamic"
        certificates.mkdir(mode=0o700)
        dynamic.mkdir(mode=0o700)
        directory = certificates / ("material-" + self.context["material_id"]) / ("revision-" + self.context["revision_id"])
        directory.mkdir(mode=0o700, parents=True)
        cert_file, key_file = directory / "tls.crt", directory / "tls.key"
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.now(timezone.utc)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, self.context["route_hosts"][0])])
        leaf = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1)).not_valid_after(now + timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([
                    x509.DNSName(host) for host in self.context["route_hosts"]]), critical=False)
                .sign(key, hashes.SHA256()))
        cert_file.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
        key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                              serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()))
        cert_file.chmod(0o600)
        key_file.chmod(0o600)
        owner = {**copy.deepcopy(self.expected["identity"]), "source": "custom",
                 "revision_id": self.context["revision_id"],
                 "fingerprint_sha256": leaf.fingerprint(hashes.SHA256()).hex()}
        return TraefikCertificateSelection(certificates, dynamic), owner, cert_file, key_file

    def compare_previous(self, snapshot, output):
        expression = self.task("Compare the complete registered predecessor envelope")["ansible.builtin.set_fact"]["custom_predecessor_unchanged"]
        context = self.previous_context(snapshot)
        context["certificate_selection_result"] = {"stdout": "TEMPLATE_OUTPUT_JSON=" + json.dumps(output)}
        return self.evaluate(expression, context), context

    def test_real_previous_snapshot_refuses_source_host_and_raw_drift_before_activation(self):
        selection, owner, certificate, key = self.domain_material()
        owner["route_hosts"] = [self.context["route_hosts"][0]]
        path = selection.binding(owner)
        raw = selection.document(owner, certificate, key)
        path.write_bytes(raw)
        request = {"identity": {field: owner[field] for field in self.expected["identity"]},
                   "operation_id": self.expected["operation_id"]}
        original = selection.observe(request)["automatic_certificate_selection"]
        self.assertTrue(self.assertions_pass(self.task("Validate the closed previous custom envelope"), self.previous_context(original)))
        unchanged, context = self.compare_previous(original, selection.observe(request))
        self.assertTrue(unchanged)
        capture = self.task("Capture the freshly qualified predecessor bytes for activation CAS")["ansible.builtin.set_fact"]["custom_selected_binding_bytes"]
        self.assertEqual(self.evaluate(capture, context), raw.decode("ascii"))
        for changed in ({**owner, "source": "native"},
                        {**owner, "route_hosts": self.context["route_hosts"]}):
            path.write_bytes(selection.document(changed, certificate, key))
            self.assertFalse(self.compare_previous(original, selection.observe(request))[0])
        drifted = raw + b"\n"
        path.write_bytes(drifted)
        self.assertFalse(self.compare_previous(original, selection.observe(request))[0])
        desired = {**owner, "route_hosts": self.context["route_hosts"]}
        verify = Mock()
        with self.assertRaises(CertificateSelectionError):
            selection.activate(desired, certificate, key, raw, verify)
        verify.assert_not_called()
        self.assertEqual(path.read_bytes(), drifted)

    def test_union_target_and_current_restoration_use_fresh_snapshots_and_desired_only_replay(self):
        selection, owner, certificate, key = self.domain_material()
        current = {**owner, "route_hosts": self.context["route_hosts"][:1]}
        union = owner
        target = {**owner, "route_hosts": self.context["route_hosts"][1:]}
        path = selection.binding(current)
        original = selection.document(current, certificate, key)
        path.write_bytes(original)
        verify = Mock()
        for previous, desired in ((current, union), (union, target), (target, current)):
            request = {"identity": {field: previous[field] for field in self.expected["identity"]},
                       "operation_id": self.expected["operation_id"]}
            snapshot = selection.observe(request)["automatic_certificate_selection"]
            self.assertTrue(self.compare_previous(snapshot, selection.observe(request))[0])
            selection.activate(desired, certificate, key, snapshot["expected_binding"].encode("ascii"), verify)
            selected = path.read_bytes()
            inode = path.stat().st_ino
            self.assertFalse(self.compare_previous(snapshot, selection.observe(request))[0])
            selection.activate(desired, certificate, key, snapshot["expected_binding"].encode("ascii"), verify)
            self.assertEqual((path.read_bytes(), path.stat().st_ino), (selected, inode))
            observed = selection.observe_custom({"identity": {field: desired[field] for field in self.expected["identity"]}})
            self.assertTrue(observed["custom_certificate_binding"]["present"])
            self.assertEqual(observed["custom_certificate_binding"]["route_hosts"], desired["route_hosts"])
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(verify.call_count, 6)

    def test_previous_custom_replay_requires_requested_identity_and_every_ordered_trusted_host(self):
        task = self.task("Require exact requested custom serving for original-request replay")
        context = {**self.previous_context(), "binding_valid": True, "binding_present": True,
                   "custom_certificate_observation": self.observation()}
        self.assertTrue(self.assertions_pass(task, context))
        for field in ("material_id", "revision_id", "content_digest", "leaf_fingerprint_sha256",
                      "route_hosts", "binding_count", "host_count", "classification"):
            value = copy.deepcopy(context)
            value["custom_certificate_observation"][field] = None
            self.assertFalse(self.assertions_pass(task, value))
        for field, changed in (("hostname", "foreign.example.test"), ("status", "expired"),
                               ("trusted", False), ("trusted", None), ("fingerprint_sha256", "f" * 64)):
            for index in range(2):
                value = copy.deepcopy(context)
                value["custom_certificate_observation"]["hosts"][index][field] = changed
                self.assertFalse(self.assertions_pass(task, value))
        value = copy.deepcopy(context)
        value["custom_certificate_observation"]["hosts"].reverse()
        self.assertFalse(self.assertions_pass(task, value))


if __name__ == "__main__":
    unittest.main()
