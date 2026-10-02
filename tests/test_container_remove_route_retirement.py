"""Whole-final opt-in composes strict route owners without changing node removal."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

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
        argv = task["command"]["argv"]
        identity = {key: "synthetic-" + key for key in (
            "organization_id", "deployment_id", "server_id", "gateway_id", "node_id", "revision_id", "identity_digest",
        )}
        env = Environment(undefined=StrictUndefined)
        env.filters["to_json"] = json.dumps
        observation = {"presence": "absent", "digest": "a" * 64}
        argument = env.from_string(argv[-1]).render(app_route_retirement={"topology": identity}, retirement_after=observation)
        result = subprocess.run([sys.executable, "-c", argv[2], argument], check=True, capture_output=True, text=True)
        output = json.loads(result.stdout.removeprefix("TEMPLATE_OUTPUT_JSON="))
        self.assertEqual(output["route_retirement"], {"version": 1, "identity": identity, "observation": observation})
        self.assertFalse(task["changed_when"])


if __name__ == "__main__":
    unittest.main()
