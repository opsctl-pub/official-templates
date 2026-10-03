"""Closed local allocation contracts; real daemon coverage is retained separately."""
import base64
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from uuid import uuid4
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("local_resource", ROOT / "catalog/ansible/scripts/local_resource.py")
resource = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(resource)
ORG = "00000000-0000-4000-8000-000000000001"
VOLUME = "00000000-0000-4000-8000-000000000002"
SERVER = "00000000-0000-4000-8000-000000000003"
BACKING = "00000000-0000-4000-8000-000000000004"


def request(kind="Volume", **changes):
    value = dict(protocol=resource.PROTOCOL, kind=kind, action="create", organization_id=ORG,
                 resource_id=VOLUME, server_id=SERVER, generation=1)
    if kind == "Volume":
        value.update(backing_id=BACKING, requested_bytes=64 * 1024**2)
    value.update(changes)
    return value


def completed(value=b"", code=0):
    return subprocess.CompletedProcess([], code, stdout=value)


def inspected(value, **changes):
    scope = changes.pop("scope", "local")
    options = changes.pop("options", None)
    identity = dict(name=resource.locator(value), driver="local" if value["kind"] == "Volume" else "bridge",
                    labels=resource.labels(value), incarnation="created" if value["kind"] == "Volume" else "a" * 64)
    identity.update(changes)
    row = list(identity.values())
    if value["kind"] == "Network":
        row.extend([scope, False, 0])
    else:
        row.extend([scope, options])
    return completed(json.dumps(row).encode())


class NativeDocker:
    """File-local Popen transport; actual invoke bounds and accounting still run."""

    def __init__(self, value, directory, *, present=True, change=None, attachments=0,
                 unavailable=False, inspect_failed=False, create_failed=False, containers=None,
                 container_inspect_failed=False):
        self.value = value
        self.directory = directory
        self.present = present
        self.change = change or {}
        self.attachments = attachments
        self.unavailable = unavailable
        self.inspect_failed = inspect_failed
        self.create_failed = create_failed
        self.containers = containers or {}
        self.container_inspect_failed = container_inspect_failed
        self.calls = []

    def __call__(self, argv, *, stdout, stderr, env):
        assert env == {} and stderr == subprocess.DEVNULL
        assert argv[0] == "/usr/bin/docker"
        self.calls.append(argv)
        family, action = argv[1:3]
        if family == "container":
            if action == "ls":
                assert argv[3:] == ["--all", "--quiet", "--no-trunc"]
                output = "\n".join(self.containers).encode()
                code = 0
            elif action == "inspect":
                assert argv[3:5] == ["--format", '[{{json .Id}},{{json .Mounts}}]']
                assert argv[-2] == "--" and argv[-1] in self.containers
                output = json.dumps([argv[-1], self.containers[argv[-1]]["mounts"]]).encode()
                code = int(self.container_inspect_failed)
            else:
                raise AssertionError("Unexpected container command")
            stdout.write(output)
            return Process(code)
        assert family == ("volume" if self.value["kind"] == "Volume" else "network")
        code, output = 0, b""
        if self.unavailable:
            code = 1
        elif action == "ls":
            assert argv[3:] == ["--format", "{{.Name}}", "--filter",
                                 "name=^" + resource.locator(self.value) + "$"]
            output = resource.locator(self.value).encode() if self.present else b""
        elif action == "inspect":
            assert argv[-2:] == ["--", resource.locator(self.value)]
            assert argv[3] == "--format"
            if self.inspect_failed:
                code = 1
            elif ".Mountpoint" in argv[4]:
                output = json.dumps([self.directory, self.change.get("incarnation", "created"),
                                     self.change.get("labels", resource.labels(self.value))]).encode()
            else:
                row = json.loads(inspected(self.value, **self.change).stdout)
                if family == "network":
                    row[-1] = self.attachments
                output = json.dumps(row).encode()
        elif action == "create":
            assert argv[3:5] == ["--driver", "local" if family == "volume" else "bridge"]
            assert argv[-1] == resource.locator(self.value)
            expected = []
            for key, label in sorted(resource.labels(self.value).items()):
                expected.extend(["--label", key + "=" + label])
            assert argv[5:-1] == expected
            self.present = True
            code = 1 if self.create_failed else 0
        elif action == "rm":
            assert argv[3:] == ["--", resource.locator(self.value) if family == "volume" else "a" * 64]
            self.present = False
        else:
            raise AssertionError("Unexpected native command")
        stdout.write(output)
        return Process(code)


class Process:
    def __init__(self, code=0):
        self.returncode = code
        self.killed = False
        self.waited = False

    def poll(self):
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self):
        self.waited = True
        return self.returncode


class LocalResourceTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        tools = patch.object(resource.shutil, "which", return_value="/usr/bin/docker")
        tools.start()
        self.addCleanup(tools.stop)

    def transport(self, value, **kwargs):
        return NativeDocker(value, self.directory.name, **kwargs)

    def test_no_paths_options_or_uncaptured_volume_deletion_before_inspection(self):
        for value in (request(action="delete"), request(locator="arbitrary"), request(driver="nfs"),
                      request(generation=True), request(requested_bytes=0), request(backing_id="bad"),
                      request("Network", backing_id=BACKING), request(server_id="bad")):
            with self.subTest(value=value), patch.object(resource.subprocess, "Popen") as native:
                with self.assertRaises((resource.ResourceError, ValueError)):
                    resource.execute(value)
                native.assert_not_called()

    def test_create_uses_derived_name_labels_no_options_and_observes_identity(self):
        for kind in ("Volume", "Network"):
            value = request(kind)
            transport = self.transport(value, present=False)
            with self.subTest(kind=kind), patch.object(resource.subprocess, "Popen", side_effect=transport):
                output = resource.execute(value)
            self.assertEqual(output["presence"], "present")
            self.assertTrue(output["changed"])
            self.assertFalse(output["quota_enforced"])
            self.assertEqual(sum(argv[2] == "create" for argv in transport.calls), 1)
            self.assertFalse(any("--opt" in argv for argv in transport.calls))
            if kind == "Volume":
                self.assertEqual(output["observed_used_bytes"], 0)
                self.assertGreater(output["observed_free_bytes"], 0)
                self.assertEqual(sum(".Mountpoint" in " ".join(argv) for argv in transport.calls), 1)

    def test_lost_create_response_recovers_only_labeled_allocation(self):
        value = request()
        transport = self.transport(value, present=False, create_failed=True)
        with patch.object(resource.subprocess, "Popen", side_effect=transport):
            output = resource.execute(value)
        self.assertEqual(output["presence"], "present")
        self.assertFalse(output["changed"])

    def test_existing_exact_volume_is_observed_without_mutation(self):
        value = request(expected_incarnation="created")
        transport = self.transport(value)
        with patch.object(resource.subprocess, "Popen", side_effect=transport):
            output = resource.execute(value)
        self.assertFalse(output["changed"])
        self.assertTrue(all(argv[2] in {"ls", "inspect"} for argv in transport.calls))
        self.assertEqual(sum(argv[2] == "ls" for argv in transport.calls), 3)

    def test_foreign_labels_driver_or_incarnation_fail_without_mutation(self):
        value = request(expected_incarnation="created")
        for change in ({"labels": {}}, {"driver": "nfs"}, {"incarnation": "replacement"}):
            transport = self.transport(value, change=change)
            with self.subTest(change=change), patch.object(resource.subprocess, "Popen", side_effect=transport):
                with self.assertRaisesRegex(resource.ResourceError, "mismatch|changed"):
                    resource.execute(value)
            self.assertEqual([argv[2] for argv in transport.calls], ["ls", "inspect"])

    def test_local_volume_rejects_wrong_scope_and_nonempty_driver_options(self):
        value = request(expected_incarnation="created")
        for change in ({"scope": "global"}, {"options": {"device": "/host/path"}},
                       {"options": {"type": "nfs"}}, {"options": "invalid"}):
            transport = self.transport(value, change=change)
            with self.subTest(change=change), patch.object(resource.subprocess, "Popen", side_effect=transport):
                with self.assertRaisesRegex(resource.ResourceError, "identity_mismatch"):
                    resource.execute(value)
            self.assertEqual([argv[2] for argv in transport.calls], ["ls", "inspect"])
        for options in (None, {}):
            with self.subTest(options=options), patch.object(resource.subprocess, "Popen",
                    side_effect=self.transport(value, change={"options": options})):
                self.assertEqual(resource.execute(value)["presence"], "present")

    def test_network_delete_requires_captured_id_and_rejects_replacement(self):
        for identity in (None, "", "bad", "A" * 64):
            with self.subTest(identity=identity), patch.object(resource.subprocess, "Popen") as native:
                with self.assertRaisesRegex(resource.ResourceError, "identity_required|invalid_request"):
                    resource.execute(request("Network", action="delete", expected_incarnation=identity))
                native.assert_not_called()
        value = request("Network", action="delete", expected_incarnation="a" * 64)
        transport = self.transport(value, change={"incarnation": "b" * 64})
        with patch.object(resource.subprocess, "Popen", side_effect=transport):
            with self.assertRaisesRegex(resource.ResourceError, "incarnation_changed"):
                resource.execute(value)
        self.assertEqual([argv[2] for argv in transport.calls], ["ls", "inspect"])

    def test_absence_is_distinct_from_unreachable_daemon_or_failed_inspect(self):
        value = request(action="observe")
        with patch.object(resource.subprocess, "Popen", side_effect=self.transport(value, present=False)):
            self.assertEqual(resource.execute(value)["presence"], "absent")
        for options in ({"unavailable": True}, {"inspect_failed": True}):
            with patch.object(resource.subprocess, "Popen", side_effect=self.transport(value, **options)):
                with self.assertRaisesRegex(resource.ResourceError, "unavailable|unknown"):
                    resource.execute(value)

    def test_empty_network_removal_uses_exact_id_then_proves_absence(self):
        value = request("Network", action="delete", expected_incarnation="a" * 64)
        transport = self.transport(value)
        with patch.object(resource.subprocess, "Popen", side_effect=transport):
            output = resource.execute(value)
        self.assertEqual(transport.calls[4], ["/usr/bin/docker", "network", "rm", "--", "a" * 64])
        self.assertEqual(output["presence"], "absent")
        self.assertEqual([argv[2] for argv in transport.calls], ["ls", "inspect", "ls", "inspect", "rm", "ls"])

    def test_nonempty_network_refuses_removal(self):
        value = request("Network", action="delete", expected_incarnation="a" * 64)
        transport = self.transport(value, attachments=1)
        with patch.object(resource.subprocess, "Popen", side_effect=transport):
            with self.assertRaisesRegex(resource.ResourceError, "in_use"):
                resource.execute(value)
        self.assertEqual([argv[2] for argv in transport.calls], ["ls", "inspect"])

    def test_volume_delete_counts_readonly_and_writable_created_exited_consumers(self):
        value = request(action="delete", expected_incarnation="created")
        for state in ("created", "exited", "running"):
            for writable in (True, False):
                container = {"state": state, "mounts": [{"Type": "volume", "Name": resource.locator(value),
                                                          "RW": writable}]}
                transport = self.transport(value, containers={"c" * 64: container})
                with self.subTest(state=state, writable=writable), patch.object(
                        resource.subprocess, "Popen", side_effect=transport):
                    with self.assertRaisesRegex(resource.ResourceError, "local_volume_in_use"):
                        resource.execute(value)
                self.assertFalse(any(argv[2] == "rm" for argv in transport.calls))
                self.assertIn(["/usr/bin/docker", "container", "ls", "--all", "--quiet", "--no-trunc"],
                              transport.calls)

    def test_volume_delete_unknown_consumer_inspection_or_mode_fails_closed(self):
        value = request(action="delete", expected_incarnation="created")
        for mount in ({"Type": "volume", "Name": resource.locator(value)},
                      {"Type": "volume", "Name": resource.locator(value), "RW": "false"},
                      {"Type": "volume", "RW": True}):
            transport = self.transport(value, containers={"c" * 64: {"mounts": [mount]}})
            with patch.object(resource.subprocess, "Popen", side_effect=transport):
                with self.assertRaisesRegex(resource.ResourceError, "observation_unknown"):
                    resource.execute(value)
            self.assertFalse(any(argv[2] == "rm" for argv in transport.calls))
        transport = self.transport(value, containers={"c" * 64: {"mounts": []}}, container_inspect_failed=True)
        with patch.object(resource.subprocess, "Popen", side_effect=transport):
            with self.assertRaisesRegex(resource.ResourceError, "observation_unknown"):
                resource.execute(value)

    def test_volume_delete_uses_exact_name_without_force_then_proves_absence(self):
        value = request(action="delete", expected_incarnation="created")
        transport = self.transport(value)
        with patch.object(resource.subprocess, "Popen", side_effect=transport):
            output = resource.execute(value)
        self.assertEqual(output["presence"], "absent")
        self.assertEqual(output["attachment_count"], 0)
        self.assertTrue(output["changed"])
        self.assertIn(["/usr/bin/docker", "volume", "rm", "--", resource.locator(value)], transport.calls)
        self.assertFalse(any("--force" in argv or "-f" in argv for argv in transport.calls))
        calls = len(transport.calls)
        with patch.object(resource.subprocess, "Popen", side_effect=transport):
            self.assertFalse(resource.execute(value)["changed"])
        self.assertEqual(transport.calls[calls:], [["/usr/bin/docker", "volume", "ls", "--format", "{{.Name}}",
                                                 "--filter", "name=^" + resource.locator(value) + "$"]])

    def test_missing_incarnation_never_allocates_replacement(self):
        value = request(expected_incarnation="old")
        transport = self.transport(value, present=False)
        with patch.object(resource.subprocess, "Popen", side_effect=transport):
            with self.assertRaisesRegex(resource.ResourceError, "incarnation_missing"):
                resource.execute(value)
        self.assertEqual([argv[2] for argv in transport.calls], ["ls"])

    def test_native_failure_timeout_and_corruption_never_disclose_output(self):
        value = request()
        for result in (OSError("private"), completed(b"private", code=1), completed(b"x" * 65537)):
            process = Process(result.returncode if not isinstance(result, Exception) else 0)
            def native(_argv, *, stdout, **_kwargs):
                if isinstance(result, Exception):
                    raise result
                stdout.write(result.stdout)
                return process
            output = io.StringIO()
            argv = ["resource", "--request", base64.b64encode(json.dumps(value).encode()).decode()]
            with patch.object(sys, "argv", argv), patch.object(resource.subprocess, "Popen", side_effect=native):
                with contextlib.redirect_stdout(output):
                    self.assertEqual(resource.main(), 1)
            self.assertNotIn("private", output.getvalue())
            self.assertEqual(set(json.loads(output.getvalue())), {"error_code"})
            if not isinstance(result, Exception):
                self.assertTrue(process.waited)

    def test_bounded_popen_timeout_kills_and_reaps_without_output(self):
        process = Process()
        process.returncode = None
        with patch.object(resource.subprocess, "Popen", return_value=process), \
                patch.object(resource.time, "monotonic", side_effect=[0, 21]):
            with self.assertRaisesRegex(resource.ResourceError, "unavailable"):
                resource.invoke("/usr/bin/docker", ["volume", "ls"])
        self.assertTrue(process.killed and process.waited)


@unittest.skipUnless(os.environ.get("OPSCTL_ISOLATED_LOCAL_RESOURCE_PROOF") == "1",
                     "requires the explicitly owned isolated Docker daemon")
class IsolatedDaemonTests(unittest.TestCase):
    def test_retained_data_exact_replay_and_empty_network_exclusion(self):
        """Run only inside disposable DinD; never accept a host/shared socket."""
        docker = resource.shutil.which("docker")
        name = resource.invoke(docker, ["info", "--format", "{{.Name}}"])
        self.assertEqual(name.returncode, 0)
        self.assertEqual(name.stdout.decode().strip(), "dev5-stateful-disposable")
        volume = request(resource_id=str(uuid4()), backing_id=str(uuid4()), organization_id=str(uuid4()))
        created = resource.execute(volume)
        observed = resource.execute({**volume, "action": "observe", "expected_incarnation": created["incarnation"]})
        self.assertEqual(created["incarnation"], observed["incarnation"])
        self.assertEqual(resource.execute(volume)["incarnation"], created["incarnation"])
        native = resource.locator(volume)
        first = resource.invoke(docker, ["run", "--rm", "-v", native + ":/data", "busybox:latest",
                                         "sh", "-c", "printf retained-synthetic > /data/proof"])
        self.assertEqual(first.returncode, 0)
        second = resource.invoke(docker, ["run", "--rm", "-v", native + ":/data:ro", "busybox:latest",
                                          "cat", "/data/proof"])
        self.assertTrue(second.returncode == 0 and second.stdout == b"retained-synthetic")
        with self.assertRaisesRegex(resource.ResourceError, "local_volume_delete_identity_required"):
            resource.execute({**volume, "action": "delete"})
        self.assertEqual(resource.execute(volume)["incarnation"], created["incarnation"])

        network = request("Network", organization_id=volume["organization_id"], resource_id=str(uuid4()))
        allocated = resource.execute(network)
        consumer = "isolated-consumer-" + uuid4().hex
        started = resource.invoke(docker, ["run", "-d", "--name", consumer, "--network", resource.locator(network),
                                           "busybox:latest", "sleep", "120"])
        self.assertEqual(started.returncode, 0)
        try:
            with self.assertRaisesRegex(resource.ResourceError, "in_use"):
                resource.execute({**network, "action": "delete", "expected_incarnation": allocated["incarnation"]})
        finally:
            stopped = resource.invoke(docker, ["rm", "-f", "--", consumer])
            self.assertEqual(stopped.returncode, 0)
        removed = resource.execute({**network, "action": "delete", "expected_incarnation": allocated["incarnation"]})
        self.assertEqual(removed["presence"], "absent")
        self.assertEqual(resource.execute({**network, "action": "observe"})["presence"], "absent")
        self.assertEqual(resource.execute(volume)["incarnation"], created["incarnation"])


if __name__ == "__main__":
    unittest.main()
