"""Offline native Ansible restoration contracts, not live runtime or TLS proof."""

import copy
import json
from pathlib import Path
import subprocess
import unittest

from jinja2 import Environment, StrictUndefined
import yaml

from test_container_deploy_native import run_tasks


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

    def execute_native(self, name, responses, context=None):
        task = self.task(name)
        fixture = [{'rc': item.returncode, 'stdout': item.stdout or '', 'stderr': item.stderr or ''}
                   for item in responses]
        result, self.calls = run_tasks([task], self.context if context is None else context, fixture)
        self.assertTrue(task["no_log"])
        return result

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
                result = self.execute_native("Restore exact prior Traefik runtime", self.restore_responses(status=status))
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                calls = self.calls
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
            with self.subTest(name=name):
                context = {**self.context, "traefik_prior_runtime_present":
                           name == "Restore exact prior Traefik runtime"}
                result = self.execute_native(name, [self.response(drift)], context)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.calls, [["docker", "inspect", "owned-proxy"]])

    def test_restore_preserves_literal_arguments_and_case_sensitive_bind_comparison(self):
        config = self.prior["Config"]
        config["Env"] = ["LITERAL=$HOME/${HOME}"]
        config["Cmd"] = ["--literal=$HOME/${HOME}"]
        config["Labels"] = {"lower": "$HOME", "Lower": "${HOME}"}
        binds = ["/fixture/a/$HOME/${HOME}:/a:ro", "/fixture/A/$HOME/${HOME}:/A:ro"]
        self.prior["HostConfig"]["Binds"] = binds
        final = copy.deepcopy(self.prior)
        final["HostConfig"]["Binds"] = list(reversed(binds))
        result = self.execute_native("Restore exact prior Traefik runtime",
                                     self.restore_responses(final=final))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        create = self.calls[2]
        self.assertEqual(create, [
            "docker", "create", "--name", "owned-proxy", "--restart", "on-failure:2",
            "--network", "host", "--workdir", "/work", "--user", "1000:1001",
            "--entrypoint", "/entrypoint.sh", "--env", "LITERAL=$HOME/${HOME}",
            "--label", "Lower=${HOME}", "--label", "lower=$HOME",
            "--volume", binds[0], "--volume", binds[1],
            "--publish", "[::1]:18443:8443/tcp", "proxy@sha256:prior",
            "--literal=$HOME/${HOME}",
        ])
        self.assertNotIn("LITERAL=$HOME", result.stdout + result.stderr)

    def test_create_or_final_verification_failure_never_claims_restoration(self):
        result = self.execute_native("Restore exact prior Traefik runtime", [
            self.response(self.current), self.response(), self.response(code=1),
        ])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(self.calls), 3)
        fields = {
            "Config": ["Image", "Cmd", "Entrypoint", "Labels", "Env", "User", "WorkingDir"],
            "HostConfig": ["NetworkMode", "RestartPolicy", "Binds", "PortBindings"],
            "State": ["Status"],
        }
        for section, keys in fields.items():
            for key in keys:
                final = copy.deepcopy(self.prior)
                final[section][key] = None
                with self.subTest(section=section, key=key):
                    responses = self.restore_responses()
                    responses[-1] = self.response(final)
                    result = self.execute_native("Restore exact prior Traefik runtime", responses)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('Verify exact prior', result.stdout)
        mark = self.task("Mark exact runtime restoration complete")
        self.assertGreater(self.tasks.index(mark), self.tasks.index(self.task("Restore exact prior Traefik runtime")))
        self.assertTrue(self.predicates(mark["when"], self.context))
        self.assertNotIn("traefik_runtime_restored", yaml.safe_dump(self.task("Restore exact prior Traefik runtime")))

    def test_fresh_cleanup_exact_identity_absence_and_remaining_presence_refusal(self):
        name = "Remove failed fresh Traefik replacement"
        context = {**self.context, "traefik_prior_runtime_present": False}
        result = self.execute_native(name, [self.response(self.current), self.response(), self.response(code=1)], context)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.calls, [
            ["docker", "inspect", "owned-proxy"], ["docker", "rm", "-f", "owned-proxy"],
            ["docker", "inspect", "owned-proxy"],
        ])
        result = self.execute_native(name, [self.response(self.current), self.response(), self.response(self.current)], context)
        self.assertNotEqual(result.returncode, 0)
        result = self.execute_native(name, [self.response(self.current), self.response(code=1)], context)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(self.calls), 2)
        context = {**context, "traefik_restore_current": None}
        result = self.execute_native(name, [self.response(code=1), self.response(code=1)], context)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(len(self.calls), 2)

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
