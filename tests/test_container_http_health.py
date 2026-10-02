"""Permanent tests for shell-less private container HTTP health probing."""
import argparse
import contextlib
import http.server
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "container_http_health", ROOT / "catalog/ansible/scripts/container_http_health.py",
)
health = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(health)
ORG = "c758ae41-ab81-498b-89b7-7ac49a9acf45"
DEPLOYMENT = "d58f84eb-1c5b-5841-93a0-4f71af57e291"
REVISION = "19391c2a-830e-4039-879a-1aa7617e788d"


def arguments(**changes):
    values = dict(container="managed-app", organization=ORG,
                  deployment=DEPLOYMENT, revision=REVISION, port="18176", path="/")
    values.update(changes)
    return argparse.Namespace(**values)


def inspected(**changes):
    values = dict(identity="a" * 64, pid=123, running=True, started="start",
                  managed="true", organization=ORG, deployment=DEPLOYMENT, revision=REVISION)
    values.update(changes)
    return list(values.values())


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.tools = patch.object(health.shutil, "which", side_effect=lambda name: "/usr/bin/" + name)
        self.open = patch.object(health.os, "open", return_value=19)
        self.close = patch.object(health.os, "close")
        self.tools.start()
        self.open_mock = self.open.start()
        self.close_mock = self.close.start()
        self.addCleanup(self.tools.stop)
        self.addCleanup(self.open.stop)
        self.addCleanup(self.close.stop)

    def result(self, value=None, code=0):
        return subprocess.CompletedProcess([], code, stdout=json.dumps(value).encode())

    def test_exact_network_namespace_host_interpreter_and_no_output(self):
        item = inspected()
        with patch.object(health.subprocess, "run", side_effect=[
            self.result(item), self.result(item), self.result(code=0), self.result(item),
        ]) as run:
            health.probe(arguments())
        self.open_mock.assert_called_once_with("/proc/123/ns/net", health.os.O_RDONLY)
        self.close_mock.assert_called_once_with(19)
        command = run.call_args_list[2]
        self.assertEqual(command.args[0], [
            "/usr/bin/nsenter", "--net=/proc/self/fd/19", "--", sys.executable,
            "-I", "-c", health.HTTP_PROBE, "18176", "/",
        ])
        self.assertEqual(command.kwargs["pass_fds"], (19,))
        self.assertEqual(command.kwargs["env"], {})
        self.assertEqual(command.kwargs["stdout"], subprocess.DEVNULL)
        self.assertEqual(command.kwargs["stderr"], subprocess.DEVNULL)
        self.assertEqual(command.kwargs["timeout"], 10)
        self.assertNotIn("exec", run.call_args_list[0].args[0])

    def test_http_failure_and_timeout_close_namespace(self):
        item = inspected()
        for outcome in (self.result(code=2), subprocess.TimeoutExpired("probe", 10)):
            with self.subTest(outcome=type(outcome).__name__):
                with patch.object(health.subprocess, "run", side_effect=[
                    self.result(item), self.result(item), outcome, self.result(item),
                ]):
                    with self.assertRaises((health.HealthError, subprocess.TimeoutExpired)):
                        health.probe(arguments())
        self.assertEqual(self.close_mock.call_count, 2)

    def test_missing_stopped_and_wrong_identity(self):
        cases = [self.result(code=1)] + [self.result(inspected(**change)) for change in (
            {"running": False}, {"pid": 0}, {"pid": True}, {"organization": "other"},
            {"managed": "false"}, {"deployment": "other"}, {"revision": "other"},
        )]
        for outcome in cases:
            with self.subTest(outcome=outcome.stdout):
                with patch.object(health.subprocess, "run", return_value=outcome):
                    with self.assertRaises(health.HealthError):
                        health.probe(arguments())
        self.open_mock.assert_not_called()

    def test_replacement_before_and_after_request(self):
        item = inspected()
        for changed in (inspected(identity="b" * 64), inspected(pid=456), inspected(started="later")):
            for after in (False, True):
                with self.subTest(after=after, changed=changed):
                    sequence = [self.result(item), self.result(changed)]
                    if after:
                        sequence = [self.result(item), self.result(item), self.result(), self.result(changed)]
                    with patch.object(health.subprocess, "run", side_effect=sequence):
                        with self.assertRaisesRegex(health.HealthError, "target_changed"):
                            health.probe(arguments())

    def test_invalid_inputs_do_not_inspect(self):
        for change in (
            {"port": "0"}, {"port": "65536"}, {"port": "1;id"}, {"port": "-1"},
            {"path": "https://outside/"}, {"path": "//outside/"}, {"path": "/\r\nAuthorization:x"},
            {"path": "/#fragment"}, {"container": "--all"}, {"organization": "bad"},
        ):
            with self.subTest(change=change):
                with patch.object(health.subprocess, "run") as run:
                    with self.assertRaises((health.HealthError, ValueError)):
                        health.probe(arguments(**change))
                    run.assert_not_called()

    def test_missing_nsenter_is_explicit(self):
        with patch.object(health.shutil, "which", return_value=None):
            with self.assertRaisesRegex(health.HealthError, "nsenter_unavailable"):
                health.probe(arguments())

    def test_legacy_restoration_requires_exact_original_labels(self):
        args = arguments(deployment="", revision="")
        with patch.object(health.subprocess, "run", return_value=self.result(
            inspected(deployment=None, revision=None),
        )):
            self.assertEqual(health.inspect("/usr/bin/docker", args)[6:], [None, None])
        with patch.object(health.subprocess, "run", return_value=self.result(inspected())):
            with self.assertRaises(health.HealthError):
                health.inspect("/usr/bin/docker", args)

    def test_main_timeout_is_sanitized(self):
        argv = ["probe"]
        for key, value in vars(arguments()).items():
            argv.extend(["--" + key, value])
        output = io.StringIO()
        with patch.object(sys, "argv", argv), patch.object(health, "probe", side_effect=
                subprocess.TimeoutExpired("secret-command", 10, output=b"secret")):
            with contextlib.redirect_stdout(output):
                self.assertEqual(health.main(), 1)
        self.assertEqual(json.loads(output.getvalue()), {"error_code": "container_health_timeout"})


class HttpTests(unittest.TestCase):
    def test_actual_get_200_non200_redirect_and_no_body_disclosure(self):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                status = {"/": 200, "/failed": 503, "/redirect": 302}[self.path]
                self.send_response(status)
                if status == 302:
                    self.send_header("Location", "/")
                self.end_headers()
                self.wfile.write(b"private-response-must-not-appear")

            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for path, expected in (("/", 0), ("/failed", 2), ("/redirect", 2)):
                result = subprocess.run([sys.executable, "-I", "-c", health.HTTP_PROBE,
                                         str(server.server_port), path],
                                        capture_output=True, timeout=10,
                                        env={"HTTP_PROXY": "http://127.0.0.1:1"})
                self.assertEqual(result.returncode, expected)
                self.assertEqual(result.stdout, b"")
                self.assertEqual(result.stderr, b"")
        finally:
            server.shutdown()
            server.server_close()
            thread.join()

    def test_playbook_delivery_auto_fallback_and_restoration(self):
        text = (ROOT / "catalog/ansible/playbooks/container_deploy.yml").read_text()
        self.assertNotIn('"docker", "exec", name, "sh"', text)
        self.assertNotIn('docker exec "{{ container_name }}" sh', text)
        self.assertIn("ansible.builtin.script:", text)
        self.assertIn("base64.b64decode", text)
        self.assertIn("effective_health_mode in ['host', 'container', 'traefik']", text)
        self.assertNotIn("- health_mode != 'auto'", text)
        self.assertIn('until: docker_health_status.stdout.strip() == "healthy"', text)
        self.assertIn("until: health_result_host.status == 200", text)
        self.assertIn("until: container_health_exec.rc == 0", text)
        self.assertIn('"--revision", str((config.get("Labels") or {}).get("com.opsctl.revision_id") or "")', text)


if __name__ == "__main__":
    unittest.main()
