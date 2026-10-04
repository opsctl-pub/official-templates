"""Offline command/framing tests, not Ansible, live runtime, TLS or atomic proof."""

import copy
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

from jinja2 import Environment, StrictUndefined
import yaml


CATALOG = Path(__file__).parents[1] / "catalog/ansible"


def named(tasks, name):
    """Locate the actual owner task without duplicating its implementation."""
    for task in tasks:
        if task.get("name") == name:
            return task
        for section in ("tasks", "block", "rescue"):
            if section in task:
                result = named(task[section], name)
                if result is not None:
                    return result
    return None


class GatewayRuntimeRestoreTests(unittest.TestCase):
    def setUp(self):
        self.tasks = yaml.safe_load((CATALOG / "tasks/traefik_gateway_runtime_restore.yml").read_text())
        self.proxy = yaml.safe_load((CATALOG / "playbooks/traefik_proxy.yml").read_text())
        self.cleanup = yaml.safe_load((CATALOG / "tasks/traefik_gateway_dns_challenge_cleanup.yml").read_text())
        self.environment = Environment(undefined=StrictUndefined)
        self.environment.filters.update({"to_json": json.dumps,
                                         "combine": lambda left, right: {**left, **right}})
        self.prior = {
            "Id": "prior-id", "Name": "/owned-proxy",
            "Config": {"Image": "proxy@sha256:prior", "Cmd": ["--providers.file.directory=/dynamic"],
                       "Entrypoint": ["/entrypoint.sh"], "Env": ["TEST_FLAG=enabled"],
                       "Labels": {"com.opsctl.owner": "synthetic-owner", "component": "proxy"},
                       "User": "1000:1001", "WorkingDir": "/work"},
            "HostConfig": {"NetworkMode": "host",
                           "RestartPolicy": {"Name": "on-failure", "MaximumRetryCount": 2},
                           "Binds": ["/fixture/dynamic:/dynamic:ro"],
                           "PortBindings": {"8443/tcp": [{"HostIp": "::1", "HostPort": "18443"}]}},
            "State": {"Status": "running"},
        }
        self.current = copy.deepcopy(self.prior)
        self.current["Id"] = "replacement-id"
        self.current["Mounts"] = [{"Destination": "/dynamic", "RW": False}]
        self.context = {"traefik_prior_runtime": self.prior,
                        "traefik_restore_current": self.current,
                        "traefik_container_name": "owned-proxy",
                        "traefik_replacement_started": True,
                        "traefik_prior_runtime_present": True}

    def task(self, name, tasks=None):
        result = named(self.tasks if tasks is None else tasks, name)
        self.assertIsNotNone(result, name)
        return result

    def predicates(self, expressions, context):
        if isinstance(expressions, str):
            expressions = [expressions]
        return all(self.environment.compile_expression(expression)(**context)
                   for expression in expressions)

    def execute_inline(self, name, responses, context=None):
        task = self.task(name)
        rendered = self.environment.from_string(task["shell"]).render(
            **(self.context if context is None else context),
        )
        body = rendered.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
        with patch("subprocess.run", side_effect=responses) as commands:
            self.commands = commands
            exec(compile(body, str(CATALOG / "tasks/traefik_gateway_runtime_restore.yml"), "exec"), {})
        self.assertTrue(task["no_log"])
        self.assertTrue(self.predicates(task["failed_when"], {
            task["register"]: {"rc": 1},
        }))

    def response(self, value=None, code=0):
        return subprocess.CompletedProcess([], code, json.dumps([value]) if value is not None else "", "")

    def restore_responses(self, final=None, status="running"):
        restored = copy.deepcopy(self.prior) if final is None else final
        restored["State"]["Status"] = status
        responses = [self.response(self.current), self.response(), self.response(), self.response()]
        if status != "running":
            responses.append(self.response())
        responses.append(self.response(restored))
        return responses

    def test_actual_restore_reconstructs_complete_runtime_and_prior_status(self):
        for status in ("running", "paused", "exited"):
            with self.subTest(status=status):
                self.prior["State"]["Status"] = status
                self.execute_inline("Restore exact prior Traefik runtime", self.restore_responses(status=status))
                calls = [call.args[0] for call in self.commands.call_args_list]
                self.assertEqual(calls[0], ["docker", "inspect", "owned-proxy"])
                self.assertEqual(calls[1], ["docker", "rm", "-f", "owned-proxy"])
                self.assertEqual(calls[2], [
                    "docker", "create", "--name", "owned-proxy", "--restart", "on-failure:2",
                    "--network", "host", "--workdir", "/work", "--user", "1000:1001",
                    "--entrypoint", "/entrypoint.sh", "--env", "TEST_FLAG=enabled",
                    "--label", "com.opsctl.owner=synthetic-owner", "--label", "component=proxy",
                    "--volume", "/fixture/dynamic:/dynamic:ro", "--publish", "[::1]:18443:8443/tcp",
                    "proxy@sha256:prior", "--providers.file.directory=/dynamic",
                ])
                self.assertEqual(calls[3], ["docker", "start", "owned-proxy"])
                if status != "running":
                    self.assertEqual(calls[4], ["docker", "pause" if status == "paused" else "stop", "owned-proxy"])
                self.assertEqual(calls[-1], ["docker", "inspect", "owned-proxy"])

    def test_second_read_identity_drift_refuses_before_remove_or_create(self):
        drift = {**self.current, "Id": "foreign-id"}
        for name in ("Restore exact prior Traefik runtime", "Remove failed fresh Traefik replacement"):
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, "runtime_changed_before"):
                self.execute_inline(name, [self.response(drift)])
            self.assertEqual(self.commands.call_count, 1)
            self.assertEqual(self.commands.call_args.args[0], ["docker", "inspect", "owned-proxy"])

    def test_create_or_final_verification_failure_never_claims_restoration(self):
        failure = subprocess.CalledProcessError(1, ["docker", "create"])
        with self.assertRaises(subprocess.CalledProcessError):
            self.execute_inline("Restore exact prior Traefik runtime", [
                self.response(self.current), self.response(), failure,
            ])
        self.assertEqual(self.commands.call_count, 3)
        fields = {
            "Config": ["Image", "Cmd", "Entrypoint", "Labels", "Env", "User", "WorkingDir"],
            "HostConfig": ["NetworkMode", "RestartPolicy", "Binds", "PortBindings"],
            "State": ["Status"],
        }
        for section, keys in fields.items():
            for key in keys:
                final = copy.deepcopy(self.prior)
                final[section][key] = None
                with self.subTest(section=section, key=key), \
                        self.assertRaisesRegex(RuntimeError, "prior_runtime_restore_mismatch"):
                    responses = self.restore_responses()
                    responses[-1] = self.response(final)
                    self.execute_inline("Restore exact prior Traefik runtime", responses)
        mark = self.task("Mark exact runtime restoration complete")
        self.assertGreater(self.tasks.index(mark), self.tasks.index(self.task("Restore exact prior Traefik runtime")))
        self.assertTrue(self.predicates(mark["when"], self.context))
        self.assertNotIn("traefik_runtime_restored", self.task("Restore exact prior Traefik runtime")["shell"])

    def test_fresh_cleanup_exact_identity_absence_and_remaining_presence_refusal(self):
        name = "Remove failed fresh Traefik replacement"
        self.execute_inline(name, [self.response(self.current), self.response(), self.response(code=1)])
        self.assertEqual([call.args[0] for call in self.commands.call_args_list], [
            ["docker", "inspect", "owned-proxy"], ["docker", "rm", "-f", "owned-proxy"],
            ["docker", "inspect", "owned-proxy"],
        ])
        self.assertTrue(self.commands.call_args_list[1].kwargs["check"])
        with self.assertRaisesRegex(RuntimeError, "failed_fresh_traefik_still_present"):
            self.execute_inline(name, [self.response(self.current), self.response(), self.response(self.current)])
        context = {**self.context, "traefik_restore_current": None}
        self.execute_inline(name, [self.response(code=1), self.response(code=1)], context)
        self.assertEqual(self.commands.call_count, 2)

    def test_actual_owner_predicate_rejects_replacement_drift_and_accepts_prior_or_absent(self):
        task = self.task("Refuse restoration over another runtime owner")
        context = {**self.context, "traefik_image": self.current["Config"]["Image"],
                   "traefik_replacement_details": copy.deepcopy(self.current),
                   "traefik_managed_labels": {"component": "proxy"},
                   "traefik_command_args": self.current["Config"]["Cmd"]}
        expressions = task["assert"]["that"]
        self.assertTrue(self.predicates(expressions, context))
        for section, key in ((None, "Id"), ("Config", "Image"), ("Config", "Cmd"),
                             ("Config", "Labels"), ("HostConfig", "NetworkMode"), (None, "Mounts")):
            current = copy.deepcopy(self.current)
            if section is None:
                current[key] = "foreign"
            else:
                current[section][key] = {} if key == "Labels" else "foreign"
            with self.subTest(key=key):
                self.assertFalse(self.predicates(expressions, {**context, "traefik_restore_current": current}))
        for current in (None, self.prior):
            self.assertTrue(self.predicates(expressions, {**context, "traefik_restore_current": current}))

    def test_dashboard_snapshot_cas_and_safe_path_predicates(self):
        generation = self.task("Refuse restoration over a different dashboard generation")["ansible.builtin.assert"]["that"]
        for prior, desired in (("cHJpb3I=", "ZGVzaXJlZA=="), (None, "ZGVzaXJlZA=="), ("cHJpb3I=", None)):
            for current in (prior, desired, "Zm9yZWlnbg=="):
                context = {"traefik_dashboard_snapshot": {"prior": prior, "desired": desired},
                           "traefik_dashboard_restore_stat": {"stat": {"exists": current is not None}},
                           "traefik_dashboard_restore_bytes": {"content": current}}
                self.assertEqual(self.predicates(generation, context), current in (prior, desired))
        safe = {"exists": True, "isreg": True, "islnk": False, "uid": 0, "mode": "0600", "size": 100}
        expressions = self.task("Refuse unsafe dashboard restoration path")["ansible.builtin.assert"]["that"]
        self.assertTrue(self.predicates(expressions, {"traefik_dashboard_restore_stat": {"stat": safe}}))
        for change in ({"isreg": False}, {"islnk": True}, {"uid": 1000}, {"mode": "0644"}, {"size": 65537}):
            self.assertFalse(self.predicates(expressions, {"traefik_dashboard_restore_stat": {"stat": {**safe, **change}}}))
        self.assertTrue(self.predicates(expressions, {"traefik_dashboard_restore_stat": {"stat": {"exists": False}}}))
        copy_task = self.task("Restore prior private dashboard bytes atomically")["ansible.builtin.copy"]
        self.assertFalse(copy_task["unsafe_writes"])
        self.assertEqual(copy_task["dest"], "{{ traefik_dashboard_snapshot.path }}")
        absence = self.task("Restore original dashboard absence")
        self.assertEqual(absence["ansible.builtin.file"], {"path": "{{ traefik_dashboard_snapshot.path }}", "state": "absent"})

    def test_proxy_rescue_only_before_retirement_and_before_restoration_complete(self):
        task = self.task("Restore prior managed runtime after later setup failure", self.proxy)
        self.assertTrue(self.predicates(task["when"], {"traefik_dashboard_changed": True}))
        self.assertTrue(self.predicates(task["when"], {"traefik_replacement_started": True}))
        self.assertFalse(self.predicates(task["when"], {}))
        for guard in ("traefik_runtime_restored", "traefik_dashboard_retirement_started"):
            self.assertFalse(self.predicates(task["when"], {"traefik_replacement_started": True, guard: True}))

    def test_cleanup_preserves_preexisting_referenced_and_unobserved_credentials(self):
        inspect = self.task("Inspect runtime before removing newly staged broker credential", self.cleanup)
        details = self.task("Read failed gateway runtime identity", self.cleanup)
        remove = self.task("Remove unreferenced newly staged broker credential", self.cleanup)
        path = "/fixture/broker-token"
        staged = {"dns_challenge_token_file": path, "dns_challenge_token_installed": {"stat": {"exists": False}}}
        self.assertTrue(self.predicates(inspect["when"], staged))
        self.assertFalse(self.predicates(inspect["when"], {**staged, "dns_challenge_token_installed": {"stat": {"exists": True}}}))
        self.assertFalse(self.predicates(details["when"], {"failed_gateway_info": {"failed": True}}))
        self.assertFalse(self.predicates(details["when"], {"failed_gateway_info": {}}))
        self.assertFalse(self.predicates(remove["when"], staged))
        for current, removable in ((None, True), ({"Config": {"Env": []}}, True),
                                   ({"Config": {"Env": ["HTTPREQ_PASSWORD_FILE=" + path]}}, False)):
            context = {**staged, "failed_gateway_details": current}
            self.assertEqual(self.predicates(remove["when"], context), removable)
            self.assertFalse(self.predicates(remove["when"], {**context, "dns_challenge_token_installed": {"stat": {"exists": True}}}))
        self.assertEqual(remove["ansible.builtin.file"], {"path": "{{ dns_challenge_token_file }}", "state": "absent"})
        self.assertTrue(remove["no_log"])


if __name__ == "__main__":
    unittest.main()
