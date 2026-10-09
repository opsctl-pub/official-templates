"""Production controller boundaries with finite external-transport substitutions.

Root ownership, Docker observations, policy/systemd effects and timed flock are
modeled, not live enforcement. Tasks/helpers execute; no user payload executes.
"""

import copy
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest

import yaml


CATALOG = Path(__file__).resolve().parents[1] / 'catalog/ansible'
OPERATION = '00000000-0000-4000-8000-000000000001'
CONTAINER = 'd' * 64


def transport():
    """Answer only queued native calls; never implement a daemon or policy engine."""
    root = Path(os.environ['CONTROLLER_TEST_ROOT'])
    tool = sys.argv[2]
    args = sys.argv[3:]
    with (root / 'calls.jsonl').open('a') as stream:
        stream.write(json.dumps({'tool': tool, 'argv': args}) + '\n')
    if tool == 'stat':
        mode = format(stat.S_IMODE(Path(args[-1]).stat().st_mode), 'o')
        print('0:' + mode)
        return 0
    if tool == 'flock':
        index = args.index('-w')
        wait = float(args[index + 1])
        literal = args[:index] + args[index + 2:]
        try:
            result = subprocess.run(['/usr/bin/flock', *literal],
                                    pass_fds=(int(literal[-1]),), timeout=wait)
            return result.returncode
        except subprocess.TimeoutExpired:
            return 75
    responses = json.loads((root / 'responses.json').read_text())[tool]
    cursor = root / (tool + '.cursor')
    index = int(cursor.read_text()) if cursor.exists() else 0
    if index >= len(responses):
        return 91
    cursor.write_text(str(index + 1))
    response = responses[index]
    if response.get('ignore_term'):
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    if response.get('sleep'):
        time.sleep(response['sleep'])
    os.write(1, response.get('stdout', '').encode('utf-8'))
    return response.get('rc', 0)


def named(tasks, name):
    """Select one actual task, retaining its assertions and native control flow."""
    return copy.deepcopy(next(task for task in tasks if task['name'] == name))


class UserAnsibleControllerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='controller-contract-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.sentinel = self.root / 'sentinel'
        self.sentinel.write_bytes(b'unrelated sentinel')
        self.sentinel.chmod(0o640)
        self.prepare = yaml.safe_load((CATALOG / 'tasks/user_ansible_controller_prepare.yml').read_text())
        self.cleanup = yaml.safe_load((CATALOG / 'tasks/user_ansible_controller_cleanup.yml').read_text())
        self.play = yaml.safe_load((CATALOG / 'playbooks/user_ansible_controller.yml').read_text())[0]
        self.carrier = {
            'operation_id': OPERATION, 'source_digest': 'a' * 64, 'input_digest': 'b' * 64,
            'image': 'qualified.invalid/ansible@sha256:' + 'c' * 64,
            'uid': os.getuid(), 'gid': os.getgid(), 'entrypoint': 'playbook.yml',
            'targets': [{'address': '192.0.2.3'}],
            'limits': {'cpu_millicores': 100, 'memory_mib': 64, 'tmpfs_mib': 1,
                       'pids': 8, 'timeout_seconds': 20, 'log_bytes': 128},
        }

    def bind_transport(self, responses):
        (self.root / 'responses.json').write_text(json.dumps(responses))
        for path in self.root.glob('*.cursor'):
            path.unlink()
        (self.root / 'calls.jsonl').unlink(missing_ok=True)
        for tool in [*responses, 'stat', 'flock']:
            path = self.bin / tool
            path.write_text('#!/bin/sh\nexec ' + sys.executable + ' '
                            + str(Path(__file__).resolve()) + ' --transport ' + tool + ' "$@"\n')
            path.chmod(0o700)

    def environment(self):
        return {**os.environ, 'CONTROLLER_TEST_ROOT': str(self.root),
                'PATH': str(self.bin) + ':' + os.environ['PATH'],
                'HOME': str(self.root), 'TMPDIR': str(self.root),
                'ANSIBLE_LOCAL_TEMP': str(self.root / 'local'),
                'ANSIBLE_REMOTE_TEMP': str(self.root / 'remote')}

    def calls(self):
        path = self.root / 'calls.jsonl'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def run_tasks(self, tasks, variables=None, cleanup=None, exports=None):
        """Execute loaded task bodies locally, retaining failures and safe facts."""
        facts = self.root / 'facts.json'
        summary = {key: '{{ ' + key + ' | default(none) }}' for key in (exports or [])}
        summary['failed'] = '{{ regression_failed | default(false) }}'
        procedure = {'block': tasks, 'rescue': [
            {'ansible.builtin.set_fact': {'regression_failed': True}}],
            'always': (cleanup or []) + [
                {'ansible.builtin.set_fact': {'regression_summary': summary}},
                {'ansible.builtin.copy': {'dest': str(facts), 'mode': '0600',
                                         'content': '{{ regression_summary | to_json }}'}}]}
        invocation = self.root / 'play.yml'
        invocation.write_text(yaml.safe_dump([{
            'hosts': 'all', 'gather_facts': False, 'become': False,
            'vars': {**self.play['vars'], 'template_execution': self.carrier,
                     'ansible_python_interpreter': sys.executable, **(variables or {})},
            'tasks': [self.play['tasks'][0],
                      {'ansible.builtin.set_fact': {'regression_context': True, **(variables or {})}}, procedure,
                      {'ansible.builtin.fail': {'msg': 'Observed task refusal'},
                       'when': 'regression_failed | default(false)'}],
        }], sort_keys=False))
        result = subprocess.run(['ansible-playbook', '-i', '127.0.0.1,', '-c', 'local', str(invocation)],
                                env=self.environment(), stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=100)
        self.assertTrue(facts.exists(), result.stdout + result.stderr)
        self.assertEqual(self.sentinel.read_bytes(), b'unrelated sentinel')
        self.assertEqual(stat.S_IMODE(self.sentinel.stat().st_mode), 0o640)
        return result, json.loads(facts.read_text())

    def private_cleanup(self):
        return named(self.cleanup, 'Release only revalidated fresh private material')

    def source_identity(self, source):
        observed = source.stat()
        return {'stat': {'dev': observed.st_dev, 'inode': observed.st_ino}}

    def test_fresh_source_ownership_preserves_all_authenticated_regular_modes(self):
        """Actual same-UID ownership tasks; no privileged mapping or mount proof."""
        workspace = self.root / 'fresh-source'
        workspace.mkdir(mode=0o700)
        parent = workspace / 'nested'
        parent.mkdir(mode=0o700)
        originals = {}
        for mode in (0o600, 0o644, 0o700, 0o755):
            path = parent / format(mode, '04o')
            payload = bytes(range(256)) + b'{{ literal }} ${HOME}'
            path.write_bytes(payload)
            path.chmod(mode)
            originals[path] = (payload, mode)
        keys = self.root / 'keys'
        keys.mkdir(mode=0o700)
        for name in ('credential', 'inputs.json'):
            (keys / name).write_bytes(b'private synthetic fixture')
            (keys / name).chmod(0o600)
        result, facts = self.run_tasks([
            named(self.prepare, 'Observe the accepted workspace before changing only fresh ownership'),
            named(self.prepare, 'Require its actual private directory identity'),
            named(self.prepare, 'Give only fresh delivered files the qualified nonroot ownership'),
        ], {'controller_source_workspace': str(workspace)},
            exports=['controller_source_identity'])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(facts['controller_source_identity']['stat']['mode'], '0700')
        for path, (payload, mode) in originals.items():
            self.assertEqual(path.read_bytes(), payload)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)
            self.assertEqual((path.stat().st_uid, path.stat().st_gid), (os.getuid(), os.getgid()))
        for directory in (workspace, parent, keys):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        for name in ('credential', 'inputs.json'):
            self.assertEqual((keys / name).read_bytes(), b'private synthetic fixture')
            self.assertEqual(stat.S_IMODE((keys / name).stat().st_mode), 0o600)
        self.assertNotIn('private synthetic fixture', result.stdout + result.stderr)

    def test_reentry_precedes_allocation_and_reservation_failure_cleans_only_fresh_source(self):
        record = self.root / 'existing'
        record.mkdir(mode=0o700)
        marker = record / 'marker'
        marker.write_bytes(b'existing invocation')
        identity = record.stat()
        selected = {
            'Bind finite native names to the exact Operation',
            'Refuse re-entry instead of renewing or redispatching an invocation',
            'Retain existing invocation liability without adopting or redispatching it',
            'Require an unallocated invocation record',
            'Allocate private local variables for the accepted materialization procedure',
            'Invoke accepted byte delivery without importing user code',
            'Allocate this exact root-controlled invocation record',
            'Record allocation before further changes',
        }
        tasks = [copy.deepcopy(child) for task in self.prepare
                 for child in [task, *task.get('block', [])] if child['name'] in selected]
        next(task for task in tasks if task['name'].startswith('Bind finite'))[
            'ansible.builtin.set_fact']['controller_record'] = str(record)
        delivery = next(task for task in tasks if task['name'].startswith('Invoke accepted'))
        delivery.pop('ansible.builtin.command')
        delivery['ansible.builtin.file'] = {'path': str(self.root / 'delivery-called'), 'state': 'touch'}
        result, facts = self.run_tasks(tasks, cleanup=[self.cleanup[0], self.private_cleanup()],
                                      exports=['controller_process_closed', 'controller_material_cleanup'])
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertFalse(facts['controller_process_closed'])
        self.assertEqual(facts['controller_material_cleanup'], 'retained')
        self.assertFalse((self.root / 'delivery-called').exists())
        self.assertEqual(list(self.root.glob('opsctl-controller-delivery-*')), [])
        self.assertEqual(record.stat().st_ino, identity.st_ino)
        self.assertEqual(list(record.iterdir()), [marker])
        fresh = self.root / 'fresh-source'
        fresh.mkdir(mode=0o700)
        (fresh / 'playbook.yml').write_bytes(b'not executed')
        result, facts = self.run_tasks([
            named(self.prepare, 'Allocate this exact root-controlled invocation record'),
            named(self.prepare, 'Record allocation before further changes')], {
                'controller_record': str(record), 'controller_source_workspace': str(fresh),
                'controller_source_identity': self.source_identity(fresh)},
            cleanup=[self.cleanup[0], self.private_cleanup()],
            exports=['controller_process_closed', 'controller_material_cleanup', 'controller_record_owned'])
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIsNone(facts['controller_record_owned'])
        self.assertTrue(facts['controller_process_closed'])
        self.assertEqual(facts['controller_material_cleanup'], 'removed')
        self.assertFalse(fresh.exists())
        self.assertEqual(marker.read_bytes(), b'existing invocation')
        self.assertEqual(record.stat().st_ino, identity.st_ino)

    def test_frozen_stopped_container_and_policy_deadline_precede_release(self):
        record = self.root / 'record'
        (record / 'gate').mkdir(parents=True)
        proc = self.root / 'proc/123'
        (proc / 'ns').mkdir(parents=True)
        namespace = self.root / 'namespace'
        namespace.touch()
        (proc / 'ns/net').symlink_to(namespace)
        (proc / 'cgroup').write_text('0::/payload\n')
        cgroup = self.root / 'cgroup/payload'
        cgroup.mkdir(parents=True)
        for name, value in {'memory.max': '67108864', 'memory.swap.max': '0',
                            'pids.max': '8', 'cpu.max': '10000 100000'}.items():
            (cgroup / name).write_text(value)
        create = named(self.prepare, 'Create only the stopped trusted gate with bounded writable mounts')
        options = create.pop('community.docker.docker_container')
        create.pop('register')
        create['ansible.builtin.set_fact'] = {'regression_create_arguments': options}
        observed = {
            'Id': CONTAINER, 'State': {'Running': False, 'Pid': 0},
            'Config': {'Labels': {'opsctl.operation': OPERATION},
                       'User': str(os.getuid()) + ':' + str(os.getgid()),
                       'Entrypoint': ['/bin/sh', '/run/opsctl-gate/start.sh'],
                       'Cmd': ['/run/opsctl-gate', '/usr/local/bin/ansible-playbook', '--inventory',
                               '/run/opsctl-keys/inventory.json', '/source/playbook.yml'],
                       'WorkingDir': '/source', 'Healthcheck': {'Test': ['NONE']}},
            'HostConfig': {'ReadonlyRootfs': True, 'Privileged': False, 'Memory': 67108864,
                           'MemorySwap': 67108864, 'NanoCpus': 100000000, 'PidsLimit': 8,
                           'ShmSize': 348160, 'CapDrop': ['ALL'], 'CapAdd': [],
                           'SecurityOpt': ['no-new-privileges:true'], 'Devices': [],
                           'PidMode': '', 'IpcMode': 'private', 'UTSMode': '', 'PortBindings': {},
                           'Tmpfs': {'/dev': 'rw,nosuid,noexec,size=348160,mode=0755',
                                     '/tmp': 'rw,nosuid,nodev,size=348160,mode=0700,uid='
                                     + str(os.getuid()) + ',gid=' + str(os.getgid())},
                           'LogConfig': {'Type': 'json-file', 'Config': {'max-size': '1m', 'max-file': '2'}}},
            'Mounts': [{'Type': 'bind', 'RW': False}] * 3,
            'NetworkSettings': {'Networks': {'selected-network': {}}},
        }
        for case in ['valid', 'identity-drift', 'policy-failure']:
            with self.subTest(case=case):
                (record / 'gate/release').unlink(missing_ok=True)
                responses = {'iptables': [{}] * 13, 'systemd-run': [{}],
                             'systemctl': [{'stdout': 'active\n'}, {'stdout': 'active\n'},
                                           {'stdout': '0\n'}, {'stdout': 'active\n'}, {'stdout': '0\n'}],
                             'docker': [{}, {'stdout': CONTAINER + ' ' + OPERATION + ' 123\n'}] * 1
                             + [{'stdout': CONTAINER + ' ' + OPERATION + ' 123\n'}],
                             'nsenter': [{}] * 7 + [{'stdout': '-P OUTPUT DROP\n'}]}
                if case == 'policy-failure':
                    responses['nsenter'][2] = {'rc': 37}
                self.bind_transport(responses)
                container = copy.deepcopy(observed)
                if case == 'identity-drift':
                    container['Id'] = 'f' * 64
                start = named(self.prepare, 'Start only the trusted gate then install and observe namespace policy under the lock')
                start['ansible.builtin.shell'] = start['ansible.builtin.shell'].replace(
                    '/proc/', str(self.root / 'proc') + '/').replace('/sys/fs/cgroup', str(self.root / 'cgroup'))
                start['environment']['PATH'] = str(self.bin) + ':/usr/sbin:/usr/bin:/sbin:/bin'
                first = next(index for index, task in enumerate(self.prepare)
                             if task['name'] == 'Create an owned forwarding chain before any container starts')
                last = next(index for index, task in enumerate(self.prepare)
                            if task['name'] == 'Refuse an existing container rather than native replacement')
                tasks = copy.deepcopy(self.prepare[first:last]) + [
                    named(self.prepare, 'Retain creation uncertainty before the daemon call'), create,
                    {'ansible.builtin.set_fact': {'controller_created': {'container': {'Id': CONTAINER}},
                                                'controller_stopped': {'exists': True, 'container': container}}},
                    named(self.prepare, "Retain the stopped container's exact identity"),
                    named(self.prepare, 'Refuse changed identity or unsupported effective restrictions'),
                    named(self.prepare, 'Retain deadline uncertainty before the native allocation call'),
                    named(self.prepare, 'Install the independent host deadline before trusted-gate start'),
                    named(self.prepare, 'Require the exact deadline timer active'), start]
                result, facts = self.run_tasks(tasks, {
                    'controller_record': str(record), 'controller_unit': 'selected-unit',
                    'controller_source_workspace': str(self.root / 'source'),
                    'controller_network_name': 'selected-network', 'controller_bridge': 'br-selected',
                    'controller_chain': 'OCselected'}, exports=['regression_create_arguments'])
                self.assertEqual(result.returncode, 0 if case == 'valid' else 2, result.stdout + result.stderr)
                args = facts['regression_create_arguments']
                self.assertEqual((args['state'], args['detach'], args['pull']), ('present', True, 'never'))
                self.assertFalse(args['privileged'])
                self.assertTrue(args['read_only'])
                self.assertEqual(args['cap_drop'], ['ALL'])
                self.assertEqual(args['capabilities'], [])
                self.assertEqual(args['memory_swap'], args['memory'])
                self.assertEqual(args['command'], observed['Config']['Cmd'])
                self.assertEqual(args['entrypoint'], observed['Config']['Entrypoint'])
                self.assertEqual(args['healthcheck'], {'test': ['NONE']})
                self.assertTrue(all(mount['read_only'] for mount in args['mounts']))
                self.assertEqual(sum(int(item.split('size=')[1].split(',')[0]) for item in args['tmpfs'])
                                 + int(args['shm_size']), 1044480)
                calls = self.calls()
                self.assertEqual((record / 'gate/release').exists(), case == 'valid')
                if case == 'identity-drift':
                    self.assertFalse(any(call['tool'] in ['systemd-run', 'docker', 'nsenter'] for call in calls))
                    continue
                timer = next(index for index, call in enumerate(calls) if call['tool'] == 'systemd-run')
                start_index = next(index for index, call in enumerate(calls) if call['tool'] == 'docker')
                self.assertLess(timer, start_index)
                self.assertIn('deadline', calls[timer]['argv'])
                self.assertEqual(calls[start_index]['argv'], ['--host', 'unix:///var/run/docker.sock', 'start', CONTAINER])
                if case == 'valid':
                    self.assertEqual(stat.S_IMODE((record / 'gate/release').stat().st_mode), 0o444)
                    namespace_calls = [call['argv'] for call in calls if call['tool'] == 'nsenter']
                    self.assertEqual(len(namespace_calls), 8)
                    self.assertTrue(all('OUTPUT' in args for args in namespace_calls))

    def helper(self, name):
        """Bind only unavailable native executable/bind paths, preserving helper logic."""
        body = (CATALOG / ('scripts/user_ansible_controller_' + name + '.sh')).read_text()
        body = body.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin',
                            'PATH=' + str(self.bin) + ':/usr/sbin:/usr/bin:/sbin:/bin')
        body = body.replace('PATH=/usr/bin:/bin', 'PATH=' + str(self.bin) + ':/usr/bin:/bin')
        body = body.replace('PATH=/usr/local/bin:/usr/bin:/bin',
                            'PATH=' + str(self.bin) + ':/usr/local/bin:/usr/bin:/bin')
        if name == 'start':
            body = body.replace('/run/opsctl-gate', str(self.root / 'gate'))
            body = body.replace('/usr/local/bin/ansible-playbook', str(self.bin / 'ansible-playbook'))
        path = self.root / (name + '.sh')
        path.write_text(body)
        return path

    def test_start_gate_withholds_rejects_closed_and_execs_only_frozen_argv(self):
        gate = self.root / 'gate'
        gate.mkdir(mode=0o755)
        self.bind_transport({'ansible-playbook': [{}]})
        helper = self.helper('start')
        command = ['/bin/sh', str(helper), str(gate), str(self.bin / 'ansible-playbook'),
                   '--inventory', '/run/opsctl-keys/inventory.json', '/source/playbook.yml']
        for closed in [True, False]:
            with self.subTest(closed=closed):
                (gate / 'closed').unlink(missing_ok=True)
                process = subprocess.Popen(command, env=self.environment(), stdin=subprocess.DEVNULL,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    time.sleep(0.2)
                    self.assertIsNone(process.poll())
                    self.assertFalse(any(call['tool'] == 'ansible-playbook' for call in self.calls()))
                    marker = gate / ('closed' if closed else 'release')
                    marker.touch()
                    marker.chmod(0o444)
                    stdout, stderr = process.communicate(timeout=5)
                    self.assertEqual(process.returncode, 75 if closed else 0, stdout + stderr)
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.communicate()
        payload = [call for call in self.calls() if call['tool'] == 'ansible-playbook']
        self.assertEqual(payload, [{'tool': 'ansible-playbook', 'argv': command[-3:]}])
        refused = subprocess.run(command[:3] + ['/bin/sh', 'arbitrary'], env=self.environment(),
                                 capture_output=True, text=True, timeout=5)
        self.assertEqual(refused.returncode, 64)
        self.assertEqual(len([call for call in self.calls() if call['tool'] == 'ansible-playbook']), 1)

    def test_close_decisions_distinguish_deadline_late_exit_exact_absence_and_uncertainty(self):
        stopped = CONTAINER + ' ' + OPERATION + ' false 0\n'
        running = CONTAINER + ' ' + OPERATION + ' true 123\n'
        cases = {
            'ordinary': ('normal', [{'stdout': stopped}] * 2, 0, 'exited:stopped'),
            'deadline': ('deadline', [{'stdout': running}, {}, {'stdout': stopped}, {'stdout': stopped}], 0, 'deadline:stopped'),
            'late-timer': ('deadline', [{'stdout': stopped}] * 2, 0, 'exited:stopped'),
            'absent': ('normal', [{'rc': 1}, {}, {'rc': 1}, {}], 0, 'absent:absent'),
            'unknown': ('normal', [{'rc': 1}, {'rc': 37}], 70, None),
            'foreign': ('normal', [{'stdout': 'f' * 64 + ' ' + OPERATION + ' true 123\n'}], 65, None),
        }
        for case, (cause, responses, expected_rc, decision) in cases.items():
            with self.subTest(case=case):
                record = self.root / case
                record.mkdir(mode=0o700)
                (record / 'container-id').write_text(CONTAINER + '\n')
                (record / 'container-id').chmod(0o600)
                self.bind_transport({'docker': responses})
                helper = self.helper('close')
                result = subprocess.run(['/bin/sh', str(helper), str(record), OPERATION, cause],
                                        env=self.environment(), stdin=subprocess.DEVNULL,
                                        capture_output=True, text=True, timeout=100)
                self.assertEqual(result.returncode, expected_rc, result.stdout + result.stderr)
                self.assertEqual((record / 'closed').exists(), decision is not None)
                if decision:
                    self.assertEqual(result.stdout, 'process_closed:' + decision + '\n')
                    self.assertEqual((record / 'close-decision').read_text(), decision.split(':')[0] + '\n')
                calls = [call['argv'] for call in self.calls() if call['tool'] == 'docker']
                self.assertTrue(all(CONTAINER in args or 'id=' + CONTAINER in args for args in calls))
                if case in ['unknown', 'foreign', 'late-timer', 'ordinary', 'absent']:
                    self.assertFalse(any('stop' in args or 'kill' in args for args in calls))
                if case == 'absent':
                    self.assertEqual(sum('ls' in args for args in calls), 2)

    def test_bounded_log_failure_keeps_original_reason_and_independent_owned_cleanup(self):
        original = self.root / 'source-original'
        original.write_bytes(b'unchanged source bytes')
        for case in ['bounded', 'failed', 'term-ignored', 'unknown-process']:
            with self.subTest(case=case):
                workspace = self.root / case
                workspace.mkdir(mode=0o700)
                delivered = workspace / 'playbook.yml'
                delivered.write_bytes(original.read_bytes())
                delivered.chmod(0o600)
                response = {'stdout': 'safe-output-' + 'é' * 200}
                if case == 'failed':
                    response = {'rc': 37}
                if case == 'term-ignored':
                    response = {'ignore_term': True, 'sleep': 30}
                self.bind_transport({'docker': [response]})
                logs = named(self.cleanup, 'Collect bounded logs independently of safe liability cleanup')
                logs['block'][0]['environment']['PATH'] = str(self.bin) + ':/usr/sbin:/usr/bin:/sbin:/bin'
                started = time.monotonic()
                result, facts = self.run_tasks([logs, self.private_cleanup()], {
                    'controller_source_workspace': str(workspace),
                    'controller_source_identity': self.source_identity(workspace),
                    'controller_container_id': CONTAINER, 'controller_close_presence': 'stopped',
                    'controller_process_closed': case != 'unknown-process',
                    'controller_material_cleanup': 'retained',
                    'controller_original_reason': 'execution_failed',
                    'controller_reason': 'execution_failed', 'controller_outcome': 'failed'},
                    exports=['controller_original_reason', 'controller_reason', 'controller_logs',
                             'controller_logs_truncated', 'controller_material_cleanup'])
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(original.read_bytes(), b'unchanged source bytes')
                self.assertEqual(facts['controller_original_reason'], 'execution_failed')
                self.assertLessEqual(len(facts['controller_logs'].encode('utf-8')), 128)
                self.assertNotIn('unchanged source bytes', result.stdout + result.stderr)
                if case == 'unknown-process':
                    self.assertTrue(workspace.exists())
                    self.assertEqual(facts['controller_material_cleanup'], 'retained')
                    self.assertEqual(self.calls(), [])
                else:
                    self.assertFalse(workspace.exists())
                    self.assertEqual(facts['controller_material_cleanup'], 'removed')
                    if case == 'bounded':
                        self.assertTrue(facts['controller_logs_truncated'])
                        self.assertEqual(facts['controller_logs'], 'safe-output-' + 'é' * 58)
                    else:
                        self.assertEqual(facts['controller_reason'], 'log_collection_failed')
                        self.assertEqual(facts['controller_logs'], '')
                if case == 'term-ignored':
                    self.assertLess(time.monotonic() - started, 25)


if __name__ == '__main__':
    if sys.argv[1:2] == ['--transport']:
        sys.exit(transport())
    unittest.main()
