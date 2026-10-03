"""Whole-final opt-in composes strict route owners without changing node removal."""
import json
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import yaml
from jinja2 import Environment, StrictUndefined


class ContainerRemoveRouteRetirementTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plays = yaml.safe_load((Path(__file__).parents[1] /
            "catalog/ansible/playbooks/container_remove.yml").read_text())

    def test_container_ownership_is_checked_before_route_effects(self):
        names = [task["name"] for task in self.plays[0]["tasks"]]
        self.assertLess(names.index("Validate exact managed identity and expected revision image"),
                        names.index("Observe explicitly qualified whole-deployment route"))
        self.assertEqual(self.plays[1]["import_playbook"], "traefik_route_converge.yml")
        self.assertEqual(self.plays[2]["import_playbook"], "caddy_route_converge.yml")

    def test_node_only_has_no_route_effect_and_each_engine_is_explicit(self):
        for play in self.plays[1:3]:
            condition = play["when"]
            template = Environment(undefined=StrictUndefined).from_string("{{ " + condition + " }}")
            self.assertEqual(template.render(), "False")
            for engine in ("traefik", "caddy", "nginx"):
                result = template.render(app_route_retirement={"topology": {"gateway_engine": engine}})
                self.assertEqual(result, str(play["import_playbook"] == engine + "_route_converge.yml"))

    def test_native_cas_and_absence_are_not_replaced_by_file_parsing(self):
        for play in self.plays[1:3]:
            self.assertEqual(play["vars"]["expected_route_observation"], "{{ retirement_before }}")
            self.assertEqual(play["vars"]["route_state"], "absent")
        observer = self.plays[3]["tasks"][0]["block"]
        self.assertTrue(observer[0]["include_tasks"].endswith("tasks/traefik_route_observation.yml"))
        self.assertTrue(observer[1]["script"].endswith("scripts/caddy_route_contract.py observe"))
        self.assertEqual(self.plays[3]["tasks"][1]["assert"]["that"],
                         "route_observation == app_route_retirement.absent")

    def test_actual_ownership_guard_accepts_matching_present_or_absent_only(self):
        block = self.plays[0]["tasks"][-1]["block"]
        condition = block[-2]["assert"]["that"][0]
        template = Environment(undefined=StrictUndefined).from_string("{{ " + condition + " }}")
        present = {"presence": "present", "hosts": ["owned.example.test"], "route_port": 18176,
                   "https": True, "redirect_http_to_https": True, "middlewares": [],
                   "backend_identity_class": "loopback", "digest": "a" * 64}
        absent = {"presence": "absent", "hosts": [], "route_port": None, "https": None,
                  "redirect_http_to_https": None, "middlewares": [], "backend_identity_class": None,
                  "digest": "b" * 64}
        for observation, accepted in (
            (present, True), (absent, True), ({**present, "hosts": ["other.example.test"]}, False),
            ({**present, "digest": "c" * 64}, False), ({**absent, "presence": "unknown"}, False),
            ({**absent, "unrecognized": True}, False),
        ):
            with self.subTest(observation=observation["presence"], accepted=accepted):
                self.assertEqual(template.render(route_observation=observation,
                    app_route_retirement={"present": present, "absent": absent}), str(accepted))

    def test_output_is_structured_exact_identity_and_observation_not_boolean(self):
        task = next(task for task in self.plays[-1]["tasks"] if "route retirement evidence" in task["name"])
        identity = {key: "synthetic-" + key for key in (
            "organization_id", "deployment_id", "server_id", "gateway_id", "node_id", "revision_id", "identity_digest",
        )}
        env = Environment(undefined=StrictUndefined)
        env.filters["to_json"] = json.dumps
        observation = {"presence": "absent", "digest": "a" * 64}
        from jinja2.nativetypes import NativeEnvironment
        receipt = NativeEnvironment(undefined=StrictUndefined).from_string(
            task["set_fact"]["removal_route_receipt"]).render(
                app_route_retirement={"topology": identity}, retirement_after=observation)
        envelope = next(task for task in self.plays[-1]["tasks"]
                        if task["name"] == "Assemble complete verified removal output")
        result = subprocess.run([sys.executable, "-c", envelope["command"]["argv"][2],
            "", "{}", json.dumps(receipt), "", "false"], check=True, capture_output=True, text=True)
        output = json.loads(result.stdout.removeprefix("TEMPLATE_OUTPUT_JSON="))
        self.assertEqual(output["route_retirement"], {"version": 1, "identity": identity, "observation": observation})
        self.assertFalse(envelope["changed_when"])

    def test_authoritative_envelope_preserves_all_applicable_proofs(self):
        task = next(task for task in self.plays[-1]["tasks"]
                    if task["name"] == "Assemble complete verified removal output")
        request = {key: "synthetic-" + key for key in (
            "organization_id", "deployment_id", "server_id", "operation_id", "revision_id")}
        request["previous"] = {"container_id": "a" * 64}
        proof = {**{key: value for key, value in request.items() if key != "previous"},
                 "protocol": "opsctl-local-runtime/1", "container_id": "a" * 64,
                 "presence": "absent", "ready": False, "attachments": [], "detached_attachments": []}
        route = {"version": 1, "identity": {"deployment_id": request["deployment_id"]},
                 "observation": {"presence": "absent"}}
        drain = {"contract_digest": "b" * 64, "container_id": "a" * 64, "absent": True}
        marker = lambda value: "TEMPLATE_OUTPUT_JSON=" + json.dumps(value)
        for runtime in (False, True):
            for routed in (False, True):
                for drained in (False, True):
                    with self.subTest(runtime=runtime, routed=routed, drained=drained):
                        result = subprocess.run([sys.executable, "-c", task["command"]["argv"][2],
                            marker({"local_runtime": proof}) if runtime else "",
                            json.dumps(request if runtime else {}), json.dumps(route if routed else {}),
                            marker({"connection_drain_removal": drain}) if drained else "",
                            json.dumps(drained)], capture_output=True, text=True)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        expected = {}
                        if runtime:
                            expected["local_runtime"] = proof
                        if routed:
                            expected["route_retirement"] = route
                        if drained:
                            expected["connection_drain_removal"] = drain
                        if expected:
                            self.assertEqual(result.stdout.count("TEMPLATE_OUTPUT_JSON="), 1)
                            self.assertEqual(json.loads(result.stdout.removeprefix("TEMPLATE_OUTPUT_JSON=")), expected)
                        else:
                            self.assertEqual(result.stdout, "")

    def test_invalid_registered_runtime_cannot_be_reconstructed_from_desired(self):
        task = next(task for task in self.plays[-1]["tasks"]
                    if task["name"] == "Assemble complete verified removal output")
        for value in ("", "TEMPLATE_OUTPUT_JSON={}", "TEMPLATE_OUTPUT_JSON=null",
                      "TEMPLATE_OUTPUT_JSON={\"local_runtime\":true}", "untrusted\nTEMPLATE_OUTPUT_JSON={}"):
            with self.subTest(value=value):
                result = subprocess.run([sys.executable, "-c", task["command"]["argv"][2],
                    value, '{"previous":{}}', "{}", "", "false"], capture_output=True, text=True)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr.strip(), "Canonical removal output is invalid.")

    def drain_packet(self):
        def digest(value):
            return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        contract = {
            "root_id": "11111111-1111-4111-8111-111111111111",
            "organization_id": "22222222-2222-4222-8222-222222222222",
            "deployment_id": "33333333-3333-4333-8333-333333333333",
            "revision_id": "44444444-4444-4444-8444-444444444444",
            "container_name": "owned-drain-app", "app_slug": "owned-app",
            "image_ref": "owned-image@sha256:" + "e" * 64,
            "backend_url": "http://10.100.0.1:18176", "timeout_s": 1,
            "route_observation": {"presence": "present", "remaining": "10.100.0.2"},
        }
        chain = "ocd" + digest({"root_id": contract["root_id"], "container_id": "b" * 64})[:20]
        receipt = {
            "version": 1, "contract_digest": digest(contract),
            "gateway": {"container_id": "a" * 64, "route_observation": contract["route_observation"],
                        "observed_at": "2020-01-01T00:00:00Z"},
            "runtime": {"container_id": "b" * 64, "netns_inode": 12345,
                        "listen_port": 3000, "active_inbound_connections": 0,
                        "barrier_id": chain, "observed_at": "2020-01-01T00:00:00Z"},
        }
        receipt["digest"] = digest(receipt)
        return {"contract": contract, "receipt": receipt}, chain, digest

    def drain_script(self):
        task = next(task for task in self.plays[-1]["tasks"]
                    if task["name"] == "Verify opt-in HTTP drain barrier and exact inbound-zero before removal")
        self.assertEqual(task["when"], "app_connection_drain is defined")
        return task["command"]["argv"][2]

    def test_lost_removal_callback_requires_same_local_receipt_and_both_absences(self):
        """Docker absence doubles exercise replay logic, not real removal causality."""
        packet, chain, _ = self.drain_packet()
        for failure in (None, "local_receipt", "original_id_present", "name_unknown"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                custody = Path(directory)
                local = json.loads(json.dumps(packet["receipt"]))
                if failure == "local_receipt":
                    local["runtime"]["netns_inode"] += 1
                path = custody / (chain + ".json")
                path.write_text(json.dumps(local))
                path.chmod(0o600)
                calls = []

                def docker_inspect(argv, **kwargs):
                    calls.append(argv)
                    identity = argv[-1]
                    if failure == "original_id_present" and identity == "b" * 64:
                        return subprocess.CompletedProcess(argv, 0, "[{}]", "")
                    if failure == "name_unknown" and identity == packet["contract"]["container_name"]:
                        return subprocess.CompletedProcess(argv, 1, "", "daemon unavailable")
                    return subprocess.CompletedProcess(argv, 1, "[]", "Error: No such object: " + identity)

                with patch.object(sys, "argv", ["drain", json.dumps(packet), "remove", directory]), \
                        patch.object(subprocess, "run", side_effect=docker_inspect), \
                        patch.object(subprocess, "check_output", side_effect=ValueError("unobservable present runtime")):
                    if failure is None:
                        with self.assertRaises(SystemExit) as exited:
                            exec(compile(self.drain_script(), "official-drain", "exec"), {})
                        self.assertEqual(exited.exception.code, 0)
                        self.assertEqual([argv[-1] for argv in calls],
                                         [packet["contract"]["container_name"], "b" * 64])
                    else:
                        with self.assertRaises(ValueError):
                            exec(compile(self.drain_script(), "official-drain", "exec"), {})
                self.assertEqual(json.loads(path.read_text()), local)

    def test_partial_barrier_creation_restores_only_exact_owned_rules(self):
        """Explicit namespace/firewall doubles do not establish kernel drain proof."""
        from datetime import datetime, timezone

        for failure in ("-N", "-A", "-I", "foreign"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                packet, chain, digest = self.drain_packet()
                packet["receipt"]["gateway"]["observed_at"] = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
                packet["receipt"]["runtime"] = None
                packet["receipt"].pop("digest")
                packet["receipt"]["digest"] = digest(packet["receipt"])
                contract = packet["contract"]
                runtime = {
                    "Id": "b" * 64, "State": {"Running": True, "Pid": 123},
                    "Config": {"Image": contract["image_ref"], "Labels": {
                        "com.opsctl.managed": "true", "com.opsctl.org_id": contract["organization_id"],
                        "com.opsctl.deployment_id": contract["deployment_id"],
                        "com.opsctl.app": contract["app_slug"], "com.opsctl.revision_id": contract["revision_id"],
                    }},
                    "HostConfig": {"NetworkMode": "bridge", "PortBindings": {
                        "3000/tcp": [{"HostPort": "18176", "HostIp": "0.0.0.0"}],
                    }},
                }
                state = {"rules": ["-N " + chain, "-A " + chain + " -j DROP"] if failure == "foreign" else None,
                         "references": []}
                writes = []
                stat = os.stat

                def namespace_stat(path, *args, **kwargs):
                    if str(path) in ("/proc/123/ns/net", "/proc/1/ns/net"):
                        return SimpleNamespace(st_ino=12345 if str(path).startswith("/proc/123/") else 1)
                    return stat(path, *args, **kwargs)

                def chain_read(argv, **kwargs):
                    self.assertEqual(argv[-2:], ["-S", chain])
                    if state["rules"] is None:
                        return subprocess.CompletedProcess(argv, 1, "", "No chain/target/match by that name")
                    return subprocess.CompletedProcess(argv, 0, "\n".join(state["rules"]), "")

                def external(argv, **kwargs):
                    if argv[:2] == ("docker", "inspect"):
                        return json.dumps([runtime])
                    if argv[:2] == ("docker", "ps"):
                        return "b" * 64
                    command = list(argv[6:])
                    action = command[0]
                    if action == "-S":
                        return "\n".join(state["references"])
                    if "REJECT" in command:
                        self.assertIn(action, ("-A", "-D"))
                        self.assertEqual(command[1:], [
                            chain, "-p", "tcp", "-m", "tcp", "-j", "REJECT",
                            "--reject-with", "tcp-reset",
                        ])
                    writes.append(command)
                    if action == "-N":
                        state["rules"] = ["-N " + chain]
                    elif action == "-A":
                        state["rules"].append("-A " + " ".join(command[1:]))
                    elif action == "-I":
                        state["references"] = ["-A " + " ".join(command[1:])]
                    elif action == "-D":
                        if command[1] == "INPUT":
                            state["references"] = []
                        else:
                            state["rules"] = ["-N " + chain]
                    elif action == "-X":
                        state["rules"] = None
                    else:
                        raise AssertionError(command)
                    if action == failure:
                        raise subprocess.CalledProcessError(1, argv)
                    return ""

                with patch.object(sys, "argv", ["drain", json.dumps(packet), "observe", directory]), \
                        patch.object(os, "stat", side_effect=namespace_stat), \
                        patch.object(subprocess, "run", side_effect=chain_read), \
                        patch.object(subprocess, "check_output", side_effect=external):
                    with self.assertRaises(ValueError if failure == "foreign" else subprocess.CalledProcessError):
                        exec(compile(self.drain_script(), "official-drain", "exec"), {})
                if failure == "foreign":
                    self.assertFalse(writes)
                    self.assertEqual(state["rules"], ["-N " + chain, "-A " + chain + " -j DROP"])
                else:
                    self.assertIsNone(state["rules"])
                    self.assertFalse(state["references"])
                    self.assertNotIn("-F", [command[0] for command in writes])


if __name__ == "__main__":
    unittest.main()
