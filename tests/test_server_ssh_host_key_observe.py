"""Production observer with local discovery/root substitutions and real deadlines."""

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

import yaml


PLAYBOOK = Path(__file__).resolve().parents[1] / 'catalog/ansible/playbooks/server_ssh_host_key_observe.yml'
OPERATION = '00000000-0000-4000-8000-000000000001'
SERVER = '00000000-0000-4000-8000-000000000002'


class ServerSSHHostKeyObserveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Generate disposable native keys, never a private-key corpus."""
        cls.temporary = tempfile.TemporaryDirectory(prefix='host-key-observe-')
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.keys = {}
        for name, family, password in (
            ('ed-first', 'ed25519', ''), ('ed-second', 'ed25519', ''),
            ('ecdsa', 'ecdsa', ''), ('rsa', 'rsa', ''),
            ('encrypted', 'ed25519', 'private-pass-marker'),
        ):
            path = cls.root / ('private-path-marker-' + name)
            argv = ['/usr/bin/ssh-keygen', '-q', '-t', family, '-N', password,
                    '-C', 'comment-marker', '-f', str(path)]
            if family == 'rsa':
                argv += ['-b', '2048']
            subprocess.run(argv, check=True, capture_output=True, timeout=30)
            cls.keys[name] = path
        cls.keys['malformed'] = cls.root / 'private-path-marker-malformed'
        cls.keys['malformed'].write_bytes(b'private-file-marker-not-a-key')
        cls.keys['malformed'].chmod(0o600)
        cls.keys['unreadable'] = cls.root / 'private-path-marker-unreadable'
        cls.keys['unreadable'].write_bytes(cls.keys['ed-first'].read_bytes())
        cls.keys['unreadable'].chmod(0)
        cls.sentinel = cls.root / 'sentinel'
        cls.sentinel.write_bytes(b'unrelated-private-sentinel')
        cls.sentinel.chmod(0o640)
        cls.frozen = {
            path: (hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mode)
            for path in cls.root.iterdir() if path != cls.keys['unreadable']
        }

    def invoke(self, declarations, expected=None, case='normal', request=None):
        """Execute the whole production play; native timeout is never substituted."""
        with tempfile.TemporaryDirectory(dir=self.root) as temporary:
            directory = Path(temporary)
            configuration = directory / 'case.json'
            configuration.write_text(json.dumps({
                'paths': [str(self.keys.get(name, self.root / name)) for name in declarations],
                'sleep': case == 'timeout', 'rc': 37 if case == 'configuration-failure' else 0,
            }))
            discovery = directory / 'sshd'
            discovery.write_text(
                '#!' + sys.executable + '\n'
                'import json,os,pathlib,time\n'
                'root=pathlib.Path(os.environ["HOST_KEY_TEST_ROOT"])\n'
                'case=json.loads((root/"case.json").read_text())\n'
                'with (root/"calls").open("a") as f: f.write("discovery\\n")\n'
                'if case["sleep"]:\n'
                '    (root/"pid").write_text(str(os.getpid()))\n'
                '    time.sleep(600)\n'
                'print("config-private-marker")\n'
                'for path in case["paths"]: print("hostkey "+path)\n'
                'raise SystemExit(case["rc"])\n'
            )
            keygen = directory / 'keygen'
            keygen.write_text(
                '#!' + sys.executable + '\n'
                'import os,pathlib,sys\n'
                'root=pathlib.Path(os.environ["HOST_KEY_TEST_ROOT"])\n'
                'with (root/"calls").open("a") as f: f.write("keygen\\n")\n'
                'if "-y" in sys.argv:\n'
                '    name=pathlib.Path(sys.argv[-1]).name\n'
                '    output={"bad-wire":"ssh-ed25519 AAAA", "unsupported":"ssh-dss AAAA",'
                '"oversized":"ssh-ed25519 "+"A"*4097}.get(name)\n'
                '    if output: print(output); raise SystemExit(0)\n'
                'os.execv("/usr/bin/ssh-keygen",["/usr/bin/ssh-keygen",*sys.argv[1:]])\n'
            )
            discovery.chmod(0o700)
            keygen.chmod(0o700)
            play = copy.deepcopy(yaml.safe_load(PLAYBOOK.read_text()))
            play[0]['become'] = False
            for task in play[0]['tasks'][2]['block']:
                if 'ansible.builtin.stat' in task:
                    task['loop'] = [str(discovery), str(keygen),
                        str(directory / 'missing') if case == 'missing-deadline' else '/usr/bin/timeout']
                command = task.get('ansible.builtin.command')
                if not command:
                    continue
                self.assertEqual(command['argv'][:3], ['/usr/bin/timeout', '--signal=KILL', '10'])
                self.assertEqual((task['async'], task['poll']), (30, 1))
                self.assertFalse(command['expand_argument_vars'])
                self.assertTrue(task['no_log'])
                child = command['argv'][3]
                if child == '/usr/sbin/sshd':
                    command['argv'][3] = str(discovery)
                elif child == '/usr/bin/ssh-keygen':
                    command['argv'][3] = str(keygen)
                elif case == 'unsupported-deadline':
                    # Only unsupported help observation is substituted; deadline stays real.
                    command['argv'][3:] = ['/bin/echo', 'unsupported help']
            invocation = directory / 'play.yml'
            invocation.write_text(yaml.safe_dump(play, sort_keys=False))
            scope = {'operation_id': OPERATION, 'server_id': SERVER} if request is None else request
            parameters = directory / 'request.json'
            parameters.write_text(json.dumps({'ssh_host_key_request': scope}))
            host = {'ansible_connection': 'local', 'ansible_python_interpreter': sys.executable,
                    'ansible_async_dir': str(directory / 'async'),
                    'server_id': OPERATION if case == 'wrong-server' else SERVER}
            hosts = {'selected': host}
            if case == 'multiple-hosts':
                hosts['second'] = dict(host)
            inventory = directory / 'inventory.json'
            inventory.write_text(json.dumps({'all': {'hosts': hosts}}))
            environment = {**os.environ, 'HOME': str(directory), 'ANSIBLE_NOCOLOR': '1',
                           'ANSIBLE_LOCAL_TEMP': str(directory / 'local'),
                           'ANSIBLE_REMOTE_TEMP': str(directory / 'remote'),
                           'HOST_KEY_TEST_ROOT': str(directory)}
            started = time.monotonic()
            result = subprocess.run(
                ['ansible-playbook', '-vv', '-i', str(inventory), str(invocation),
                 '-e', '@' + str(parameters)],
                env=environment, capture_output=True, text=True, timeout=120,
            )
            output = result.stdout + result.stderr
            if case == 'timeout':
                pid = int((directory / 'pid').read_text())
                status = Path('/proc') / str(pid) / 'stat'
                state = status.read_text().split(') ', 1)[1].split()[0] if status.exists() else None
                self.assertIn(state, (None, 'Z', 'X'), 'owned sleeper alive at result return')
                self.assertLess(time.monotonic() - started, 30)
            messages = []
            for line in result.stdout.splitlines():
                if line.strip().startswith('"msg": "TEMPLATE_OUTPUT_JSON='):
                    message = json.loads('{' + line.strip().rstrip(',') + '}')['msg']
                    messages.append(json.loads(message.split('=', 1)[1]))
            calls = (directory / 'calls').read_text().splitlines() if (directory / 'calls').exists() else []
            invalid = case in ('invalid', 'wrong-server', 'multiple-hosts')
            self.assertEqual(result.returncode, 0 if expected else 2, output)
            self.assertEqual(len(messages), 0 if invalid else 1, output)
            if invalid:
                self.assertEqual(calls, [], output)
            else:
                self.assertEqual(set(messages[0]), {'ssh_host_key_observation'})
                observation = messages[0]['ssh_host_key_observation']
                self.assertEqual(set(observation), {
                    'operation_id', 'server_id', 'outcome', 'host_public_key', 'reason',
                })
                self.assertEqual((observation['operation_id'], observation['server_id']), (OPERATION, SERVER))
                public_key = None
                if expected:
                    native = subprocess.run(
                        ['/usr/bin/ssh-keygen', '-y', '-P', '', '-f', str(self.keys[expected])],
                        capture_output=True, text=True, check=True, timeout=10,
                    )
                    public_key = ' '.join(native.stdout.split()[:2])
                self.assertEqual(observation['host_public_key'], public_key, output)
                self.assertEqual(observation['outcome'], 'observed' if expected else 'unavailable')
                reason = {
                    'nine': 'candidate_limit', 'configuration-failure': 'configuration_unavailable',
                    'timeout': 'configuration_unavailable', 'missing-deadline': 'openssh_unavailable',
                    'unsupported-deadline': 'openssh_unavailable',
                }.get(case, 'observed' if expected else 'no_supported_host_key')
                self.assertEqual(observation['reason'], reason, output)
            if case in ('missing-deadline', 'unsupported-deadline'):
                self.assertEqual(calls, [], output)
            if case in ('nine', 'timeout', 'configuration-failure'):
                self.assertNotIn('keygen', calls, output)
            for marker in ('private-path-marker', 'private-file-marker', 'config-private-marker',
                           'private-pass-marker', 'unrelated-private-sentinel', 'request-private-marker'):
                self.assertNotIn(marker, output)
            for path, identity in self.frozen.items():
                self.assertEqual((hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mode), identity)
            self.assertEqual(self.keys['unreadable'].stat().st_mode & 0o777, 0)

    def test_native_family_selection_and_declaration_ties(self):
        for declarations, expected in (
            (['rsa', 'ecdsa', 'ed-first', 'ed-second'], 'ed-first'),
            (['ed-second', 'ed-first'], 'ed-second'),
            (['encrypted', 'ecdsa', 'rsa'], 'ecdsa'),
            (['malformed', 'rsa'], 'rsa'),
        ):
            with self.subTest(declarations=declarations):
                self.invoke(declarations, expected)

    def test_native_wire_refusal_and_public_only_original_preservation(self):
        for name in ('missing', 'unreadable', 'encrypted', 'malformed',
                     'unsupported', 'bad-wire', 'oversized'):
            with self.subTest(candidate=name):
                self.invoke([name])

    def test_closed_scope_refuses_before_native_reads(self):
        for request in (
            {'operation_id': OPERATION, 'server_id': SERVER, 'path': 'request-private-marker'},
            {'operation_id': OPERATION + '\n', 'server_id': SERVER},
            {'operation_id': OPERATION, 'server_id': SERVER + '\n'},
            {'operation_id': 1, 'server_id': SERVER},
        ):
            with self.subTest(request=request):
                self.invoke(['ed-first'], case='invalid', request=request)
        for case in ('wrong-server', 'multiple-hosts'):
            with self.subTest(case=case):
                self.invoke(['ed-first'], case=case)

    def test_eight_candidates_are_not_truncated_and_nine_refuse(self):
        self.invoke(['rsa', 'ecdsa', 'ed-first', 'encrypted', 'malformed',
                     'bad-wire', 'unsupported', 'oversized'], 'ed-first')
        self.invoke(['ed-first'] * 9, case='nine')

    def test_real_deadline_closes_sleeper_and_prerequisites_refuse(self):
        for case in ('timeout', 'missing-deadline', 'unsupported-deadline', 'configuration-failure'):
            with self.subTest(case=case):
                self.invoke(['ed-first'], case=case)


if __name__ == '__main__':
    unittest.main()
