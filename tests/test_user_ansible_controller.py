"""Production controller boundaries with finite external-transport substitutions.

Root ownership, Docker observations, policy/systemd effects and timed flock are
modeled, not live enforcement. Tasks/helpers execute; no user payload executes.
"""

import copy
import hashlib
from http.server import BaseHTTPRequestHandler
import json
import os
from pathlib import Path
import signal
import shutil
from socketserver import UnixStreamServer
import stat
import subprocess
import sys
import tempfile
import time
from threading import Thread
import unittest
from urllib.parse import parse_qs, urlsplit

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
        native = shutil.which('stat', path='/usr/bin:/bin')
        if native is None:
            return 91
        result = subprocess.run([native, *args], capture_output=True, text=True)
        if result.returncode:
            return result.returncode
        fields = result.stdout.strip().split(':')
        if '%u' in args[1] and not any(part in args[-1] for part in ('/keys', '/source/')):
            fields[0] = '1001' if args[-1] == os.environ.get('CONTROLLER_FOREIGN_LOCK') else '0'
        print(':'.join(fields))
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


def walk(tasks):
    """Visit loaded block bodies for explicit native transport substitutions."""
    for task in tasks:
        yield task
        for section in ('block', 'rescue', 'always'):
            yield from walk(task.get(section, []))


def delivery_transport():
    """Run actual materialization, optionally losing only its completed reply."""
    record, variables, inventory, mode = sys.argv[2:]
    record = Path(record)
    journal = json.loads((record / 'journal.json').read_text())
    if journal['phase'] != 'reserved' or journal['writer_closed'] or (record / 'keys').exists():
        return 91
    (record.parent / 'delivery-observed').write_text('journal-before-delivery')
    result = subprocess.run([
        'ansible-playbook', str(CATALOG / 'playbooks/materialize_template_files.yml'),
        '--inventory', inventory, '--limit', '127.0.0.1', '--extra-vars', '@' + variables],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)
    if mode == 'lost-reply':
        return 37 if result.returncode == 0 else 92
    os.write(1, result.stdout.encode())
    os.write(2, result.stderr.encode())
    return result.returncode


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
        self.execution = next(task['block'] for task in self.play['tasks']
                              if task['name'] == 'Prepare run and observe the frozen invocation')
        self.recovery = yaml.safe_load((CATALOG / 'tasks/user_ansible_controller_recover.yml').read_text())
        self.carrier = {
            'operation_id': OPERATION, 'source_digest': 'a' * 64, 'input_digest': 'b' * 64,
            'controller_server_id': '00000000-0000-4000-8000-000000000002',
            'image': 'qualified.invalid/ansible@sha256:' + 'c' * 64,
            'uid': os.getuid(), 'gid': os.getgid(), 'entrypoint': 'playbook.yml',
            'payload_engine': 'ansible',
            'targets': [{'address': '192.0.2.3', 'credential_file': 'synthetic-key'}],
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

    def root_tasks(self, tasks):
        """Model root UID only; retain real modes, content, device and inode checks."""
        result = []
        for original in tasks:
            task = copy.deepcopy(original)
            for section in ('block', 'rescue', 'always'):
                if section in task:
                    task[section] = self.root_tasks(task[section])
            for module in ('ansible.builtin.copy', 'ansible.builtin.file'):
                if module in task and task[module].get('owner') == 'root':
                    task[module].update(owner=os.getuid(), group=os.getgid())
            if 'ansible.builtin.shell' in task and 'environment' in task:
                task['environment']['PATH'] = str(self.bin) + ':/usr/sbin:/usr/bin:/sbin:/bin'
            result.append(task)
            register = task.get('register')
            if register in ('controller_record_identity', 'controller_record_before_remove',
                            'controller_journal_before', 'controller_journal_after',
                            'controller_recovery_after_observation'):
                result.append({'ansible.builtin.set_fact': {register:
                    '{{ ' + register + " | combine({'stat': " + register
                    + ".stat | combine({'uid': 0})}) }}"},
                    'when': task.get('when', True), 'no_log': True})
            if register in ('controller_recovery_ancestors', 'controller_private_before_remove',
                            'controller_fence_private', 'controller_recovery_markers'):
                uid = '0'
                if register == 'controller_private_before_remove':
                    uid = "0 if row.item == 'gate' else row.stat.uid"
                if register == 'controller_fence_private':
                    uid = "0 if row.item.key == 'gate' else row.stat.uid"
                result.append({'ansible.builtin.set_fact': {register:
                    "{% set ns = namespace(rows=[]) %}{% for row in " + register + ".results %}"
                    "{% if row.stat.exists | default(false) %}"
                    "{% set ns.rows = ns.rows + [row | combine({'stat': row.stat | combine({'uid': "
                    + uid + "})})] %}{% else %}{% set ns.rows = ns.rows + [row] %}"
                    "{% endif %}{% endfor %}{{ {'results': ns.rows} }}"}, 'no_log': True})
        return result

    def record_fixture(self, directory, outcome='unknown', writer_closed=True):
        record = directory / OPERATION
        record.mkdir(mode=0o700, parents=True)
        source = record / 'source'
        source.mkdir(mode=0o700)
        observed = record.stat()
        journal = {
            **{key: self.carrier[key] for key in
               ('operation_id', 'controller_server_id', 'source_digest', 'input_digest', 'uid', 'gid')},
            'record_dev': observed.st_dev, 'record_inode': observed.st_ino,
            'log_bytes': 128, 'source_parent': str(source), 'source_workspace': None,
            'source_identity': None, 'private_identities': {}, 'container_id': CONTAINER,
            'network_id': None, 'network_name': 'opsctl-user-' + OPERATION,
            'unit': 'opsctl-user-ansible-' + OPERATION,
            'chain': 'OC' + OPERATION.replace('-', '')[:20], 'chain_owned': False,
            'bridge': None, 'writer_closed': writer_closed, 'phase': 'released',
            'outcome': outcome, 'reason': 'exited' if outcome == 'succeeded' else 'execution_unknown',
            'original_reason': None, 'exit_code': 0 if outcome == 'succeeded' else None,
            'timed_out': False, 'material_cleanup': 'retained',
            'network_cleanup': 'not_allocated', 'deadline_cleanup': 'not_allocated',
            'payload_engine': self.carrier['payload_engine'],
            'source_mount': '/workspace/user' if self.carrier['payload_engine'] == 'bash' else '/source',
            'payload_argv': self.payload_argv(),
        }
        for name, value in [('container-id', CONTAINER), ('source-digest', self.carrier['source_digest']),
                            ('input-digest', self.carrier['input_digest'])]:
            (record / name).write_text(value + '\n')
            (record / name).chmod(0o600)
        if writer_closed:
            (record / 'writer-closed').write_text('closed\n')
            (record / 'writer-closed').chmod(0o600)
        (record / 'journal.json').write_text(json.dumps(journal))
        (record / 'journal.json').chmod(0o600)
        return record, journal

    def recovery_tasks(self, record, native, fence=False, removal_failed=False):
        tasks = copy.deepcopy(self.recovery)
        block = next(task['block'] for task in tasks
                     if task['name'] == 'Rejoin only the frozen nonprivate original record')
        bind = next(task for task in block if task['name'] == 'Retain safe recovery identity and unknown original liabilities')
        bind['ansible.builtin.set_fact']['controller_record'] = str(record)
        next(task for task in block if task.get('register') == 'controller_recovery_ancestors')[
            'loop'] = [str(record.parent), str(record)]
        observation = next(task for task in block if task.get('register') == 'controller_recovery_container')
        observation.pop('community.docker.docker_container_info')
        observation.pop('register')
        if native == 'unavailable':
            observation['ansible.builtin.fail'] = {'msg': 'Finite daemon transport unavailable'}
        else:
            observation['ansible.builtin.set_fact'] = {'controller_recovery_container': native}
        cleanup = self.root / 'recovery-cleanup.yml'
        cleanup_tasks = self.root_tasks(self.cleanup)
        for task in walk(cleanup_tasks):
            if 'community.docker.docker_container_info' in task:
                task.pop('community.docker.docker_container_info')
                register = task.pop('register')
                value = native if fence and register == 'controller_fence_before_remove' else {'exists': False}
                task['ansible.builtin.set_fact'] = {register: value}
            if fence and 'community.docker.docker_container' in task:
                options = task.pop('community.docker.docker_container')
                self.assertEqual(options['name'], '{{ controller_container_id }}')
                self.assertEqual(options['state'], 'absent')
                task['ansible.builtin.command'] = {'argv': ['/bin/false'] if removal_failed else [
                    '/bin/sh', '-c', 'test "$1" = "$2" && test -f "$3/closed" '
                    '&& test -f "$3/gate/closed" && rm -- "$4"', 'remove-exact',
                    '{{ controller_container_id }}', CONTAINER, str(record),
                    str(record.parent / 'container-present')], 'expand_argument_vars': False}
        cleanup.write_text(yaml.safe_dump(cleanup_tasks, sort_keys=False))
        for task in block:
            if task.get('ansible.builtin.include_tasks') == 'user_ansible_controller_cleanup.yml':
                task['ansible.builtin.include_tasks'] = str(cleanup)
            if task['name'] == 'Refresh current trusted close code only for qualified original settlement':
                task['environment']['HELPER'] = "{{ lookup('ansible.builtin.file', '" + str(
                    self.helper('close')) + "', rstrip=false) }}"
        return tasks

    def run_tasks(self, tasks, variables=None, cleanup=None, exports=None, module_defaults=None):
        """Execute loaded task bodies locally, retaining failures and safe facts."""
        facts = self.root / 'facts.json'
        facts.unlink(missing_ok=True)
        summary = {key: '{{ ' + key + ' | default(none) }}' for key in (exports or [])}
        summary['failed'] = '{{ regression_failed | default(false) }}'
        procedure = {'block': self.root_tasks(tasks), 'rescue': [
            {'ansible.builtin.set_fact': {'regression_failed': True}}],
            'always': self.root_tasks(cleanup or []) + [
                {'ansible.builtin.set_fact': {'regression_summary': summary}},
                {'ansible.builtin.copy': {'dest': str(facts), 'mode': '0600',
                                         'content': '{{ regression_summary | to_json }}'}}]}
        invocation = self.root / 'play.yml'
        carrier = {} if 'template_execution_recovery' in (variables or {}) else {'template_execution': self.carrier}
        invocation.write_text(yaml.safe_dump([{
            'hosts': 'all', 'gather_facts': False, 'become': False,
            'module_defaults': module_defaults or {},
            'vars': {**self.play['vars'], **carrier,
                     'ansible_python_interpreter': sys.executable, **(variables or {})},
            'tasks': [self.play['tasks'][0],
                      {'ansible.builtin.set_fact': {'regression_context': True, **(variables or {})}}, procedure,
                      {'ansible.builtin.fail': {'msg': 'Observed task refusal'},
                       'when': 'regression_failed | default(false)'}],
        }], sort_keys=False))
        inventory = (variables or {}).get('inventory_file', '127.0.0.1,')
        result = subprocess.run(['ansible-playbook', '-i', inventory, '-c', 'local', str(invocation)],
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

    def persist_fixture(self, record, journal):
        (record / 'journal.json').write_text(json.dumps(journal))
        (record / 'journal.json').chmod(0o600)

    def record_snapshot(self, record):
        return {str(path.relative_to(record)): (
            path.lstat().st_ino, stat.S_IMODE(path.lstat().st_mode),
            path.read_bytes() if path.is_file() else None)
            for path in [record, *record.rglob('*')]}

    def recovery_carrier(self, mode):
        return {**{key: self.carrier[key] for key in
                   ('operation_id', 'controller_server_id', 'source_digest', 'input_digest')},
                'mode': mode, 'log_bytes': 0}

    def native_observation(self, running=False):
        return {'exists': True, 'container': {
            'Id': CONTAINER, 'Config': {'Labels': {
                'opsctl.operation': OPERATION,
                'opsctl.source_digest': self.carrier['source_digest'],
                'opsctl.input_digest': self.carrier['input_digest'],
                'opsctl.payload_engine': self.carrier['payload_engine']},
                'Cmd': ['/run/opsctl-gate'] + self.payload_argv()},
            'HostConfig': {'NetworkMode': 'none' if self.carrier['payload_engine'] == 'bash'
                           else 'opsctl-user-' + OPERATION},
            'NetworkSettings': {'Networks': {'none' if self.carrier['payload_engine'] == 'bash'
                                            else 'opsctl-user-' + OPERATION: {}}},
            'State': {'Running': running, 'Pid': 123 if running else 0,
                      'ExitCode': 0, 'OOMKilled': False}}}

    def payload_argv(self):
        if self.carrier['payload_engine'] == 'bash':
            return ['/bin/bash', '--noprofile', '--norc',
                    '/workspace/user/' + self.carrier['entrypoint'], '/run/opsctl-keys/inputs.json']
        return ['/usr/bin/ansible-playbook', '--inventory', '/run/opsctl-keys/inventory.json',
                '/source/' + self.carrier['entrypoint'], '--extra-vars', '@/run/opsctl-keys/inputs.json']

    def gate_pending_fixture(self, directory, outcome='unknown'):
        self.carrier.update(payload_engine='bash', entrypoint='main.sh', targets=[])
        record, journal = self.record_fixture(directory, outcome, writer_closed=False)
        workspace = record / 'source/opsctl-template-fixture'
        workspace.mkdir(mode=0o700)
        (workspace / 'main.sh').write_bytes(b'synthetic source never executed')
        (workspace / 'main.sh').chmod(0o700)
        for name, mode in [('keys', 0o700), ('gate', 0o755)]:
            (record / name).mkdir(mode=mode)
        (record / 'keys/inputs.json').write_text('{"opsctl_inputs":{}}')
        (record / 'keys/inputs.json').chmod(0o600)
        (record / 'close.sh').write_text('#!/bin/sh\nexit 99\n')
        (record / 'close.sh').chmod(0o700)
        journal.update(phase='gate_pending', deadline_cleanup='retained',
                       source_workspace=str(workspace), source_identity={
                           **self.source_identity(workspace)['stat'], 'uid': os.getuid()},
                       private_identities={name: {
                           'dev': (record / name).stat().st_dev,
                           'inode': (record / name).stat().st_ino,
                           'uid': 0 if name == 'gate' else os.getuid(),
                           'mode': '0755' if name == 'gate' else '0700'}
                           for name in ('keys', 'gate')})
        if outcome == 'failed':
            journal.update(reason='execution_failed', exit_code=37, original_reason='delivery_failed')
        self.persist_fixture(record, journal)
        (directory / 'container-present').write_text(CONTAINER)
        native = self.native_observation()
        native['container']['Config'].update(
            Entrypoint=['/bin/sh', '/run/opsctl-gate/start.sh'], WorkingDir='/workspace/user',
            User=str(os.getuid()) + ':' + str(os.getgid()))
        native['container']['HostConfig'].update(ReadonlyRootfs=True, Privileged=False)
        native['container']['Mounts'] = [{'Type': 'bind', 'RW': False,
            'Source': str(path), 'Destination': destination} for path, destination in [
                (workspace, '/workspace/user'), (record / 'keys', '/run/opsctl-keys'),
                (record / 'gate', '/run/opsctl-gate')]]
        return record, journal, native

    def fence_carrier(self):
        return {**self.recovery_carrier('settle'), 'terminal_bash_gate_fence': {
            'controller_source_digest': 'e' * 64,
            'job_name': 'op-' + OPERATION.replace('-', ''),
            'job_uid': '00000000-0000-4000-8000-000000000003', 'condition': 'failed'}}

    def run_recovery_play(self, record, native, carrier, removal_failed=False):
        """Complete production play; only management UID and native transport modeled."""
        recovery = self.root / 'full-recovery.yml'
        recovery.write_text(yaml.safe_dump(self.root_tasks(self.recovery_tasks(
            record, native, fence='terminal_bash_gate_fence' in carrier,
            removal_failed=removal_failed)), sort_keys=False))
        play = copy.deepcopy(self.play)
        play['become'] = False
        play['vars'].update(template_execution_recovery=carrier,
                            ansible_python_interpreter=sys.executable)
        for task in walk(play['tasks']):
            if task.get('register') == 'controller_management_uid':
                task.pop('ansible.builtin.command')
                task.pop('register')
                task['ansible.builtin.set_fact'] = {'controller_management_uid': {'stdout': '0'}}
            if task.get('ansible.builtin.include_tasks') == '../tasks/user_ansible_controller_recover.yml':
                task['ansible.builtin.include_tasks'] = str(recovery)
        path = self.root / 'full-play.yml'
        path.write_text(yaml.safe_dump([play], sort_keys=False))
        result = subprocess.run(['ansible-playbook', '-i', '127.0.0.1,', '-c', 'local', str(path)],
                                env=self.environment(), stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=110)
        messages = []
        for line in result.stdout.splitlines():
            if line.strip().startswith('"msg": "'):
                messages.append(json.loads(line.strip()[7:].rstrip(',')))
        def projection(prefix):
            values = [message[len(prefix):] for message in messages if message.startswith(prefix)]
            self.assertEqual(len(values), 1, result.stdout + result.stderr)
            return json.loads(values[0])
        report = projection('TEMPLATE_OUTPUT_JSON=')['template_execution_result']
        progress = projection('Controller recovery observation: ')
        terminal = [json.loads(message.split('=', 1)[1]) for message in messages
                    if message.startswith('OPERATION_STEP=')][-1]
        self.assertEqual(self.sentinel.read_bytes(), b'unrelated sentinel')
        self.assertEqual(stat.S_IMODE(self.sentinel.stat().st_mode), 0o640)
        self.assertEqual(report['logs'], '')
        self.assertFalse(report['logs_truncated'])
        self.assertNotIn('synthetic source never executed', result.stdout + result.stderr)
        self.assertNotIn(str(record), '\n'.join(messages))
        return result, report, progress, terminal

    def fence_transports(self):
        identity = ' '.join([CONTAINER, OPERATION, self.carrier['source_digest'],
                             self.carrier['input_digest'], 'false', '0', 'bash', 'none']) + '\n'
        self.bind_transport({'docker': [{'stdout': identity}] * 2,
            'systemctl': [{'stdout': 'ActiveState=active\nLastTriggerUSecMonotonic=0\n'},
                          {}, {'rc': 3}, {'rc': 3}]})

    def test_terminal_gate_fence_full_wire_preserves_outcome_and_refuses_unsafe_release(self):
        for case in ('unknown', 'failed', 'early', 'malformed', 'foreign', 'unavailable', 'remove-failed'):
            with self.subTest(case=case):
                record, journal, native = self.gate_pending_fixture(
                    self.root / case, 'failed' if case == 'failed' else 'unknown')
                carrier = self.fence_carrier()
                if case == 'early':
                    journal['phase'] = 'deadline_pending'
                    self.persist_fixture(record, journal)
                if case == 'malformed':
                    carrier['terminal_bash_gate_fence']['condition'] = 'completed'
                if case == 'foreign':
                    native['container']['Config']['Labels']['opsctl.operation'] = 'foreign'
                self.fence_transports()
                result, report, _progress, terminal = self.run_recovery_play(
                    record, 'unavailable' if case == 'unavailable' else native,
                    carrier, removal_failed=case == 'remove-failed')
                success = case in ('unknown', 'failed')
                self.assertEqual(result.returncode, 0 if success else 2, result.stdout + result.stderr)
                self.assertEqual(terminal['status'], 'completed' if success else 'failed')
                self.assertEqual(report['outcome'], journal['outcome'])
                persisted = json.loads((record / 'journal.json').read_text())
                for field in ('outcome', 'reason', 'original_reason', 'exit_code', 'writer_closed'):
                    self.assertEqual(persisted[field], journal[field])
                self.assertFalse((record / 'writer-closed').exists())
                for field in ('material_cleanup', 'deadline_cleanup'):
                    self.assertEqual(report[field], 'removed' if success else 'retained')
                self.assertEqual((record.parent / 'container-present').exists(), not success)
                self.assertEqual((record / 'keys').exists(), not success)
                if success:
                    self.assertTrue(report['process_closed'])
                    self.assertEqual(report['exit_code'], journal['exit_code'])
                    self.assertTrue((record / 'closed').exists())
                    self.assertEqual(stat.S_IMODE((record / 'closed').stat().st_mode), 0o600)
                    self.assertEqual((record / 'close.sh').read_text(), self.helper('close').read_text())
                self.assertFalse(any('start' in call['argv'] or 'logs' in call['argv']
                                     for call in self.calls() if call['tool'] == 'docker'))

    def test_partial_finalizer_replay_preserves_history_without_material_recreation(self):
        for case in ('closed', 'linked-material', 'missing-tombstone'):
            with self.subTest(case=case):
                record, journal, _native = self.gate_pending_fixture(self.root / case, 'failed')
                producer = named(self.private_cleanup()['block'],
                    'Retain a closed nonprivate record so re-entry cannot redispatch')
                produced, facts = self.run_tasks([producer], {
                    'controller_record': str(record), 'controller_record_owned': True})
                self.assertEqual(produced.returncode, 0, produced.stdout + produced.stderr)
                self.assertFalse(facts['failed'])
                self.assertEqual((record / 'closed').read_bytes(), b'closed\n')
                self.assertEqual(stat.S_IMODE((record / 'closed').stat().st_mode), 0o600)
                for name in ('source', 'keys', 'gate'):
                    shutil.rmtree(record / name)
                (record.parent / 'container-present').unlink()
                (record / 'lock').write_bytes(b'')
                (record / 'lock').chmod(0o600)
                journal.update(phase='closed', material_cleanup='removed')
                self.persist_fixture(record, journal)
                if case == 'linked-material':
                    (record / 'keys').symlink_to(self.sentinel)
                elif case == 'missing-tombstone':
                    (record / 'closed').unlink()
                before = self.record_snapshot(record)
                self.bind_transport({'systemctl': [
                    {'stdout': 'ActiveState=inactive\nLastTriggerUSecMonotonic=0\n'},
                    {'rc': 1, 'stdout': 'PRIVATE_STOP_MARKER'}, {'rc': 3}, {'rc': 4}]})
                result, report, _progress, terminal = self.run_recovery_play(
                    record, {'exists': False}, self.fence_carrier())
                success = case == 'closed'
                self.assertEqual(result.returncode, 0 if success else 2,
                                 result.stdout + result.stderr)
                self.assertEqual(terminal['status'], 'completed' if success else 'failed')
                self.assertEqual(report['outcome'], 'failed')
                self.assertEqual(report['exit_code'], 37 if success else None)
                self.assertEqual(report['process_closed'], success)
                self.assertEqual(report['material_cleanup'], 'removed')
                self.assertEqual(report['network_cleanup'], 'not_allocated')
                self.assertEqual(report['deadline_cleanup'], 'removed' if success else 'retained')
                after = self.record_snapshot(record)
                self.assertEqual({key: value for key, value in after.items() if key != 'journal.json'},
                                 {key: value for key, value in before.items() if key != 'journal.json'})
                persisted = json.loads((record / 'journal.json').read_text())
                for field in ('outcome', 'reason', 'original_reason', 'exit_code', 'writer_closed'):
                    self.assertEqual(persisted[field], journal[field])
                self.assertFalse(persisted['writer_closed'])
                self.assertFalse((record / 'writer-closed').exists())
                self.assertNotIn('PRIVATE_STOP_MARKER', result.stdout + result.stderr)
                self.assertFalse(any(call['tool'] == 'docker' for call in self.calls()))
                calls = [call['argv'] for call in self.calls() if call['tool'] == 'systemctl']
                if success:
                    self.assertEqual([call[0] for call in calls],
                                     ['show', 'stop', 'is-active', 'is-active'])
                    self.assertEqual(persisted['deadline_cleanup'], 'removed')
                else:
                    self.assertEqual(calls, [])
                    self.assertEqual(after, before)

    def test_deadline_stop_failure_requires_both_authoritative_unit_readbacks(self):
        task = named(self.cleanup, 'Settle the independent deadline after process and private closure')
        unit = 'opsctl-user-ansible-' + OPERATION
        for case, states in (
                ('inactive', [{'rc': 3}, {'rc': 4}]),
                ('active', [{'rc': 0, 'stdout': 'active'}, {'rc': 3}]),
                ('unknown', [{'rc': 3}, {'rc': 1, 'stdout': 'PRIVATE_READ_MARKER'}])):
            with self.subTest(case=case):
                self.bind_transport({'systemctl': [{'rc': 1, 'stdout': 'PRIVATE_STOP_MARKER'},
                                                  *states]})
                result, facts = self.run_tasks([task], {
                    'controller_unit': unit, 'controller_process_closed': True,
                    'controller_writer_closed': True, 'controller_material_cleanup': 'removed',
                    'controller_deadline_cleanup': 'retained', 'controller_outcome': 'failed',
                    'controller_reason': 'execution_failed', 'controller_original_reason': 'delivery_failed',
                    'controller_execution_known': True}, exports=[
                        'controller_deadline_cleanup', 'controller_outcome',
                        'controller_reason', 'controller_original_reason'])
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(facts['controller_deadline_cleanup'],
                                 'removed' if case == 'inactive' else 'retained')
                self.assertEqual(facts['controller_outcome'], 'failed')
                self.assertEqual(facts['controller_original_reason'], 'delivery_failed')
                self.assertEqual(facts['controller_reason'],
                                 'execution_failed' if case == 'inactive' else 'cleanup_failed')
                self.assertEqual([call['argv'] for call in self.calls() if call['tool'] == 'systemctl'], [
                    ['stop', unit + '.timer', unit + '.service'],
                    ['is-active', unit + '.timer'], ['is-active', unit + '.service']])
                self.assertNotIn('PRIVATE_STOP_MARKER', result.stdout + result.stderr)
                self.assertNotIn('PRIVATE_READ_MARKER', result.stdout + result.stderr)

    def test_current_fence_tombstones_block_waiting_start_and_late_release(self):
        record, journal, native = self.gate_pending_fixture(self.root / 'delayed')
        self.fence_transports()
        gate = record / 'gate'
        helper = self.helper('start', gate)
        command = ['/bin/sh', str(helper), str(gate), str(self.bin / 'bash'), *journal['payload_argv'][1:]]
        process = subprocess.Popen(command, env=self.environment(), stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            time.sleep(0.2)
            self.assertIsNone(process.poll())
            result, report, _progress, _terminal = self.run_recovery_play(record, native, self.fence_carrier())
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 75, stdout + stderr)
            self.assertEqual(stdout, '')
            self.assertTrue(report['process_closed'])
            late = subprocess.run(['/bin/sh', '-c',
                'printf release >"$1/release.pending" && chmod 0444 "$1/release.pending" '
                '&& mv "$1/release.pending" "$1/release"', 'late-release', str(gate)],
                capture_output=True, text=True, timeout=5)
            self.assertNotEqual(late.returncode, 0)
            self.assertFalse(gate.exists())
            self.assertFalse(any(call['tool'] == 'bash' for call in self.calls()))
            self.assertFalse(json.loads((record / 'journal.json').read_text())['writer_closed'])
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()

    def test_read_only_recovery_progress_and_later_refusals_control_management(self):
        expected_keys = {'phase', 'writer_closed', 'root_closed', 'gate_closed', 'release_present',
                         'running', 'pid_zero', 'exit_code', 'oom_killed', 'timer_active',
                         'timer_never_triggered'}
        for case in ('running', 'marker', 'native', 'source', 'log'):
            with self.subTest(case=case):
                record, journal, native = self.gate_pending_fixture(self.root / case)
                native['container']['State'].update(Running=True, Pid=123)
                if case == 'marker':
                    (record / 'closed').symlink_to(self.sentinel)
                if case == 'source':
                    journal['source_digest'] = 'f' * 64
                    self.persist_fixture(record, journal)
                carrier = self.recovery_carrier('observe')
                if case == 'log':
                    carrier['log_bytes'] = 1
                self.bind_transport({'systemctl': [{
                    'stdout': 'ActiveState=active\nLastTriggerUSecMonotonic=0\n'}],
                    'docker': [{'rc': 37, 'stdout': 'private log marker'}]})
                before = self.record_snapshot(record)
                result, report, progress, terminal = self.run_recovery_play(
                    record, 'unavailable' if case == 'native' else native, carrier)
                self.assertEqual(result.returncode, 0 if case == 'running' else 2,
                                 result.stdout + result.stderr)
                self.assertEqual(terminal['status'], 'completed' if case == 'running' else 'failed')
                self.assertEqual(self.record_snapshot(record), before)
                self.assertEqual(set(progress), expected_keys)
                self.assertLessEqual(len(('Controller recovery observation: ' + json.dumps(
                    progress, ensure_ascii=True) + '\n').encode('ascii')), 2048)
                self.assertFalse(report['process_closed'])
                self.assertEqual(report['outcome'], 'unknown')
                self.assertEqual(report['material_cleanup'], 'retained')
                self.assertNotIn('private log marker', result.stdout + result.stderr)
                if case == 'running':
                    self.assertEqual(progress, dict(phase='gate_pending', writer_closed=False,
                        root_closed=False, gate_closed=False, release_present=False, running=True,
                        pid_zero=False, exit_code=0, oom_killed=False, timer_active=True,
                        timer_never_triggered=True))
                    self.assertTrue(all(call['tool'] == 'systemctl' and call['argv'][0] == 'show'
                                        for call in self.calls()))
                if case in ('marker', 'native', 'source'):
                    self.assertTrue(all(value is None for value in progress.values()))

    def test_start_failure_visibility_requires_exact_task_token_without_private_output(self):
        """Actual start/main bodies; allocation, root and native observations modeled."""
        carrier = {**self.carrier, 'payload_engine': 'bash', 'targets': [],
                   'entrypoint': 'main.sh', 'staging_directory': str(self.root / 'staged'),
                   'supplied_files': [{'path': 'main.sh', 'mode': '0700'}]}
        expected_report = {
            'operation_id': OPERATION, 'controller_server_id': carrier['controller_server_id'],
            'outcome': 'unknown', 'reason': 'execution_unknown',
            'original_reason': 'execution_unknown', 'container_id': CONTAINER,
            'exit_code': None, 'timed_out': False, 'process_closed': False,
            'material_cleanup': 'not_allocated', 'network_cleanup': 'not_allocated',
            'deadline_cleanup': 'not_allocated', 'logs': '', 'logs_truncated': False,
        }
        injected = {
            'missing': '',
            'malformed': 'controller_start_failed_check=PRIVATE_MARKER',
            'multiple': 'controller_start_failed_check=memory\ncontroller_start_failed_check=cpu',
            'trailing': 'controller_start_failed_check=memory PRIVATE_MARKER',
            'extra-newline': 'controller_start_failed_check=memory\n',
            'other-task': 'controller_start_failed_check=memory',
        }
        for case in ('tombstone', 'memory', 'timeout', 'interruption', *injected):
            with self.subTest(case=case):
                record, _journal = self.record_fixture(self.root / case, writer_closed=False)
                (record / 'gate').mkdir(mode=0o755)
                proc = record / 'proc/123'
                proc.mkdir(parents=True)
                (proc / 'cgroup').write_text('0::/payload\n')
                cgroup = record / 'cgroup/payload'
                cgroup.mkdir(parents=True)
                for key, value in {'memory.max': '67108864', 'memory.swap.max': '0',
                                   'pids.max': '8', 'cpu.max': '10000 100000'}.items():
                    (cgroup / key).write_text(value)
                identity = CONTAINER + ' ' + OPERATION + ' 123\n'
                responses = {
                    'systemctl': [{'stdout': 'active\n'}, {'stdout': '0\n'},
                                  {'stdout': 'active\n'}, {'stdout': '0\n'}],
                    'docker': [{}, {'stdout': identity}, {'stdout': 'none|none,'},
                               {'stdout': identity}],
                }
                if case == 'tombstone':
                    (record / 'closed').write_text('closed\n')
                elif case == 'memory':
                    (cgroup / 'memory.max').write_text('PRIVATE_MARKER')
                elif case == 'timeout':
                    responses['docker'][0] = {'sleep': 15, 'stdout': 'PRIVATE_MARKER'}
                self.bind_transport(responses)
                if case == 'interruption':
                    (self.bin / 'docker').write_text(
                        '#!' + sys.executable + '\nimport os, signal\n'
                        'os.kill(os.getpid(), signal.SIGTERM)\n')
                start = named(self.prepare,
                    'Start only the trusted gate then install and observe namespace policy under the lock')
                start['ansible.builtin.shell'] = start['ansible.builtin.shell'].replace(
                    '/proc/', str(record / 'proc') + '/').replace(
                    '/sys/fs/cgroup', str(record / 'cgroup'))
                start['environment']['PATH'] = str(self.bin) + ':/usr/sbin:/usr/bin:/sbin:/bin'
                if case in injected:
                    # Injected wire qualifies rescue framing, not native failure attribution.
                    start['ansible.builtin.shell'] = 'printf \'%s\\n\' "$WIRE"; exit 65'
                    start['environment']['WIRE'] = injected[case]
                    if case == 'other-task':
                        start['name'] = 'Unrelated modeled native failure'
                prepared = record / 'start-only.yml'
                prepared.write_text(yaml.safe_dump([{'ansible.builtin.set_fact': {
                    'controller_record': str(record),
                    'controller_unit': 'opsctl-user-ansible-' + OPERATION,
                    'controller_container_id': CONTAINER,
                    'controller_reason': 'execution_unknown'}}, start], sort_keys=False))
                play = copy.deepcopy(self.play)
                play['become'] = False
                play['vars'].update(template_execution=carrier,
                                    ansible_python_interpreter=sys.executable)
                for task in walk(play['tasks']):
                    if task.get('register') == 'controller_management_uid':
                        task.pop('ansible.builtin.command')
                        task.pop('register')
                        task['ansible.builtin.set_fact'] = {'controller_management_uid': {'stdout': '0'}}
                    if task.get('ansible.builtin.include_tasks') == '../tasks/user_ansible_controller_prepare.yml':
                        task['ansible.builtin.include_tasks'] = str(prepared)
                path = record / 'full-play.yml'
                path.write_text(yaml.safe_dump([play], sort_keys=False))
                result = subprocess.run([
                    'ansible-playbook', '-i', '127.0.0.1,', '-c', 'local', str(path)],
                    env=self.environment(), stdin=subprocess.DEVNULL,
                    capture_output=True, text=True, timeout=100)
                output = result.stdout + result.stderr
                messages = [json.loads(line.strip()[7:].rstrip(','))
                            for line in result.stdout.splitlines()
                            if line.strip().startswith('"msg": "')]
                visible = [message for message in messages
                           if message.startswith('Controller start failed check: ')]
                self.assertEqual(visible, ['Controller start failed check: ' + case]
                                 if case in ('tombstone', 'memory') else [], output)
                reports = [json.loads(message.split('=', 1)[1]) for message in messages
                           if message.startswith('TEMPLATE_OUTPUT_JSON=')]
                self.assertEqual(reports, [{'template_execution_result': expected_report}], output)
                self.assertEqual(result.returncode, 2, output)
                terminal = [json.loads(message.split('=', 1)[1]) for message in messages
                            if message.startswith('OPERATION_STEP=')][-1]
                self.assertEqual(terminal['status'], 'failed')
                self.assertNotIn('PRIVATE_MARKER', output)
                self.assertNotIn(str(record), '\n'.join(messages))
                self.assertFalse((record / 'gate/release').exists())
                self.assertEqual(self.sentinel.read_bytes(), b'unrelated sentinel')
                self.assertEqual(stat.S_IMODE(self.sentinel.stat().st_mode), 0o640)

    def test_final_management_predicate_preserves_fresh_success_and_refusal(self):
        tasks = [named(self.play['tasks'], name) for name in (
            'Classify management independently from the original payload outcome',
            'Publish safe terminal progress', 'Fail without echoing private native diagnostics')]
        for case in ('success', 'payload-refused', 'retained', 'cleanup', 'log', 'route'):
            with self.subTest(case=case):
                result, facts = self.run_tasks(tasks, {
                    'controller_route_qualified': case != 'route',
                    'controller_outcome': 'refused' if case == 'payload-refused' else 'succeeded',
                    'controller_reason': {'cleanup': 'cleanup_failed',
                        'log': 'log_collection_failed'}.get(case, 'exited'),
                    'controller_material_cleanup': 'retained' if case == 'retained' else 'removed',
                    'controller_network_cleanup': 'not_allocated', 'controller_deadline_cleanup': 'removed'},
                    exports=['controller_management_succeeded', 'controller_outcome'])
                self.assertEqual(result.returncode, 0 if case == 'success' else 2,
                                 result.stdout + result.stderr)
                self.assertEqual(facts['controller_management_succeeded'], case == 'success')
                self.assertEqual(facts['controller_outcome'],
                                 'refused' if case == 'payload-refused' else 'succeeded')

    def test_zero_log_observe_preserves_original_resources_and_unknown_liability(self):
        self.bind_transport({})
        for case in ('running', 'stopped', 'absent', 'unavailable', 'foreign', 'missing', 'conflict',
                     'bash-running', 'bash-stopped', 'bash-unavailable', 'missing-engine', 'bash-network'):
            with self.subTest(case=case):
                self.carrier['payload_engine'] = 'bash' if case.startswith('bash-') else 'ansible'
                directory = self.root / case
                record, journal = self.record_fixture(directory, outcome='succeeded')
                if case == 'conflict':
                    journal['input_digest'] = 'f' * 64
                    self.persist_fixture(record, journal)
                if case == 'missing':
                    (record / 'journal.json').unlink()
                if case == 'missing-engine':
                    del journal['payload_engine']
                    self.persist_fixture(record, journal)
                native = self.native_observation(running=case in ('running', 'bash-running'))
                if case == 'bash-network':
                    native['container']['HostConfig']['NetworkMode'] = 'bridge'
                if case == 'foreign':
                    native['container']['Config']['Labels']['opsctl.operation'] = 'foreign'
                if case == 'absent':
                    native = {'exists': False}
                if case in ('unavailable', 'bash-unavailable'):
                    native = 'unavailable'
                before = self.record_snapshot(record)
                result, facts = self.run_tasks(self.recovery_tasks(record, native), {
                    'template_execution_recovery': self.recovery_carrier('observe')},
                    exports=['controller_outcome', 'controller_process_closed', 'controller_exit_code',
                             'controller_logs', 'controller_logs_truncated', 'controller_material_cleanup'])
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(self.record_snapshot(record), before)
                self.assertEqual(self.calls(), [])
                self.assertEqual(facts['controller_logs'], '')
                self.assertFalse(facts['controller_logs_truncated'])
                self.assertEqual(facts['controller_outcome'],
                                 'unknown' if case in ('missing', 'conflict', 'missing-engine') else 'succeeded')
                closed = case in ('stopped', 'absent', 'bash-stopped')
                self.assertEqual(facts['controller_process_closed'], closed)
                self.assertEqual(facts['controller_exit_code'], 0 if closed else None)
                self.assertEqual(facts['controller_material_cleanup'], 'retained')
        for invalid in (True, -1, 65537):
            with self.subTest(log_bytes=invalid):
                carrier = {**self.recovery_carrier('observe'), 'log_bytes': invalid}
                result, facts = self.run_tasks(self.recovery_tasks(record, native), {
                    'template_execution_recovery': carrier}, exports=['controller_process_closed', 'controller_logs'])
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(facts['controller_process_closed'])
                self.assertEqual(facts['controller_logs'], '')
                self.assertEqual(self.calls(), [])

    def test_zero_log_settle_replay_and_pending_writer_keep_original_outcome(self):
        for case in ('settle', 'pending-writer', 'unavailable', 'bash-settle', 'bash-unavailable'):
            with self.subTest(case=case):
                self.carrier['payload_engine'] = 'bash' if case.startswith('bash-') else 'ansible'
                record, journal = self.record_fixture(
                    self.root / case, outcome='succeeded', writer_closed=case != 'pending-writer')
                workspace = record / 'source/opsctl-template-fixture'
                workspace.mkdir(mode=0o700)
                payload = workspace / 'playbook.yml'
                payload.write_bytes(b'synthetic source never executed')
                payload.chmod(0o644)
                journal.update(source_workspace=str(workspace), source_identity={
                    **self.source_identity(workspace)['stat'], 'uid': os.getuid()})
                self.persist_fixture(record, journal)
                before = self.record_snapshot(record)
                (record / 'close.sh').write_text(self.helper('close').read_text())
                (record / 'close.sh').chmod(0o700)
                identity = ' '.join([CONTAINER, OPERATION, self.carrier['source_digest'],
                                     self.carrier['input_digest']]) + ' false 0\n'
                self.bind_transport({'docker': [{'stdout': identity}] * 4})
                result, facts = self.run_tasks(self.recovery_tasks(
                    record, 'unavailable' if case.endswith('unavailable') else self.native_observation()), {
                    'template_execution_recovery': self.recovery_carrier('settle')},
                    exports=['controller_outcome', 'controller_process_closed', 'controller_exit_code',
                             'controller_logs', 'controller_logs_truncated', 'controller_material_cleanup'])
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(facts['controller_outcome'], 'succeeded')
                self.assertEqual(facts['controller_logs'], '')
                self.assertFalse(facts['controller_logs_truncated'])
                self.assertFalse(any('logs' in call['argv'] or 'start' in call['argv']
                                     for call in self.calls() if call['tool'] == 'docker'))
                persisted = json.loads((record / 'journal.json').read_text())
                self.assertEqual(persisted['outcome'], 'succeeded')
                self.assertEqual(persisted['exit_code'], 0)
                self.assertEqual(persisted['reason'], 'exited')
                if case.endswith('settle'):
                    self.assertEqual(facts['controller_material_cleanup'], 'removed')
                    self.assertFalse((record / 'source').exists())
                    self.assertTrue((record / 'closed').exists())
                    replay, replay_facts = self.run_tasks(self.recovery_tasks(record, {'exists': False}), {
                        'template_execution_recovery': self.recovery_carrier('settle')},
                        exports=['controller_outcome', 'controller_material_cleanup', 'controller_logs'])
                    self.assertEqual(replay.returncode, 0, replay.stdout + replay.stderr)
                    self.assertEqual(replay_facts['controller_outcome'], 'succeeded')
                    self.assertEqual(replay_facts['controller_material_cleanup'], 'removed')
                    self.assertEqual(replay_facts['controller_logs'], '')
                    self.assertEqual(json.loads((record / 'journal.json').read_text())['outcome'], 'succeeded')
                else:
                    self.assertEqual(facts['controller_material_cleanup'], 'retained')
                    self.assertEqual(payload.read_bytes(), b'synthetic source never executed')
                    self.assertEqual(stat.S_IMODE(payload.stat().st_mode), 0o644)
                    if case.endswith('unavailable'):
                        self.assertFalse(facts['controller_process_closed'])
                        self.assertIsNone(facts['controller_exit_code'])
                        self.assertEqual(self.calls(), [])
                        self.assertEqual({key: value for key, value in self.record_snapshot(record).items()
                                          if key != 'close.sh'}, before)

    def test_original_outcome_persistence_refuses_changed_journal_generation(self):
        first = next(index for index, task in enumerate(self.execution)
                     if task['name'] == 'Retain actual exit status independently of logs')
        for case, exit_code, cause in [('success', 0, 'exited'), ('failure', 37, 'exited'),
                                      ('deadline', 137, 'deadline'), ('generation-drift', 0, 'exited')]:
            with self.subTest(case=case):
                record, journal = self.record_fixture(self.root / case)
                self.bind_transport({})
                tasks = copy.deepcopy(self.execution[first:])
                if case == 'generation-drift':
                    tasks.insert(-1, {'ansible.builtin.copy': {
                        'dest': str(record / 'journal.json'), 'content': '{"concurrent":true}', 'mode': '0600'}})
                result, facts = self.run_tasks(tasks, {
                    'controller_journal': journal, 'controller_record': str(record),
                    'controller_record_identity': self.source_identity(record),
                    'controller_original_closure': {'stdout': 'process_closed:' + cause + ':stopped'},
                    'controller_terminal': {'container': {'State': {'ExitCode': exit_code}}}},
                    exports=['controller_outcome', 'controller_exit_code', 'controller_execution_known'])
                self.assertEqual(result.returncode, 2 if case == 'generation-drift' else 0,
                                 result.stdout + result.stderr)
                expected = 'timed_out' if cause == 'deadline' else 'failed' if exit_code else 'succeeded'
                self.assertEqual(facts['controller_outcome'], expected)
                self.assertEqual(facts['controller_exit_code'], exit_code)
                self.assertTrue(facts['controller_execution_known'])
                persisted = json.loads((record / 'journal.json').read_text())
                if case == 'generation-drift':
                    self.assertEqual(persisted, {'concurrent': True})
                else:
                    self.assertEqual(persisted['outcome'], expected)
                    self.assertEqual(persisted['exit_code'], exit_code)
                    self.assertEqual(persisted['timed_out'], cause == 'deadline')
                self.assertFalse(any(call['tool'] != 'stat' and call['tool'] != 'flock'
                                     for call in self.calls()))

    def test_full_id_network_removal_preserves_rebound_and_foreign_networks(self):
        """Installed native modules against only finite network read/refusal endpoints."""
        original, replacement = 'a' * 64, 'b' * 64
        network_name = 'opsctl-user-' + OPERATION
        block = named(self.cleanup, 'Settle only the exact owned network and policy')['block']
        selected = [named(block, name) for name in (
            'Observe exact owned network and membership before removal',
            'Refuse network cleanup with a changed owner or remaining member',
            'Remove the revalidated empty operation network',
            'Observe owned network absence', 'Require observed network removal')]

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def reply(self, status, value):
                body = json.dumps(value).encode()
                self.send_response(status)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                parsed = urlsplit(self.path)
                path = parsed.path.removeprefix('/v1.47')
                self.server.requests.append(('GET', path))
                identity = replacement if self.server.observed else original
                row = {'Id': identity, 'Name': network_name, 'Containers': {},
                       'Driver': 'bridge', 'Scope': 'local', 'Labels': {'opsctl.operation':
                           'foreign' if self.server.foreign and identity == original else OPERATION}}
                if path == '/networks':
                    rows = [row]
                    filters = json.loads(parse_qs(parsed.query).get('filters', ['{}'])[0])
                    for key, choices in filters.items():
                        if key == 'id':
                            rows = [item for item in rows if any(item['Id'].startswith(value) for value in choices)]
                        elif key == 'name':
                            rows = [item for item in rows if any(value in item['Name'] for value in choices)]
                        else:
                            self.server.unexpected.append(key)
                    self.reply(200, rows)
                elif path == '/networks/' + original and not self.server.observed:
                    self.reply(200, row)
                    self.server.observed = True
                elif path == '/networks/' + original:
                    self.reply(404, {'message': 'synthetic exact original absence'})
                else:
                    self.server.unexpected.append(path)
                    self.reply(500, {'message': 'finite transport refused unexpected read'})

            def do_DELETE(self):
                self.server.requests.append(('DELETE', urlsplit(self.path).path))
                self.reply(409, {'message': 'finite transport refused deletion'})

        for foreign in (False, True):
            with self.subTest(foreign=foreign):
                socket = self.root / ('network-' + str(foreign) + '.sock')
                server = UnixStreamServer(str(socket), Handler)
                server.observed, server.foreign = False, foreign
                server.requests, server.unexpected = [], []
                worker = Thread(target=server.serve_forever, daemon=True)
                worker.start()
                try:
                    result, facts = self.run_tasks(selected, {
                        'controller_network_id': original, 'controller_network_name': network_name,
                        'controller_cleanup_operation': OPERATION}, module_defaults={
                        'group/community.docker.docker': {'docker_host': 'unix://' + str(socket),
                            'api_version': '1.47', 'tls': False, 'validate_certs': False, 'timeout': 5}})
                finally:
                    server.shutdown()
                    worker.join(timeout=5)
                    server.server_close()
                self.assertFalse(worker.is_alive())
                self.assertEqual(result.returncode, 2 if foreign else 0, result.stdout + result.stderr)
                self.assertEqual(facts['failed'], foreign)
                self.assertTrue(server.observed)
                self.assertEqual(server.unexpected, [])
                self.assertFalse(any(method == 'DELETE' for method, _ in server.requests))
                self.assertFalse(any(path in ('/networks/' + replacement, '/networks/' + network_name)
                                     for _, path in server.requests))

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

    def test_journal_reservation_reentry_and_lost_reply_confine_delivery(self):
        self.bind_transport({})
        first = next(index for index, task in enumerate(self.prepare)
                     if task['name'] == 'Bind finite native names to the exact Operation')
        last = next(index for index, task in enumerate(self.prepare)
                    if task['name'] == 'Observe the accepted workspace before changing only fresh ownership')
        for case in ('fresh', 'lost-reply', 'reentry', 'reservation-race', 'bash-fresh'):
            with self.subTest(case=case):
                self.carrier['payload_engine'] = 'bash' if case == 'bash-fresh' else 'ansible'
                directory = self.root / case
                directory.mkdir(mode=0o700)
                record = directory / OPERATION
                stage = directory / 'staged'
                stage.mkdir(mode=0o700)
                payload = b'synthetic private source, never executed\n'
                source = stage / 'source-00'
                source.write_bytes(payload)
                source.chmod(0o400)
                self.carrier.update(staging_directory=str(stage), supplied_files=[{
                    'source': source.name, 'path': 'playbook.yml', 'mode': '0755' if case == 'bash-fresh' else '0600',
                    'size_bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest()}])
                inventory = directory / 'inventory'
                inventory.write_text('127.0.0.1 ansible_connection=local\n')
                before = None
                if case == 'reentry':
                    record.mkdir(mode=0o700)
                    (record / 'marker').write_bytes(b'existing invocation')
                    before = record.stat().st_ino
                tasks = copy.deepcopy(self.prepare[first:last])
                tasks[0]['ansible.builtin.set_fact']['controller_record'] = str(record)
                reservation = next(task['block'] for task in tasks
                                   if task['name'] == 'Reserve the exact Operation record exclusively before any delivery')
                if case == 'reservation-race':
                    reservation.insert(0, {'ansible.builtin.file': {
                        'path': str(record), 'state': 'directory', 'mode': '0700'}})
                delivery = next(child for task in tasks for child in task.get('block', [])
                                if child.get('name') == 'Invoke accepted byte delivery without importing user code')
                delivery['ansible.builtin.command']['argv'] = [
                    sys.executable, str(Path(__file__).resolve()), '--delivery', str(record),
                    '{{ controller_delivery_variables.path }}', '{{ inventory_file }}', case]
                result, facts = self.run_tasks([
                    named(self.execution, "Freeze only the validated engine's native execution bindings"),
                    *tasks], {'inventory_file': str(inventory)},
                    cleanup=[self.cleanup[0], self.private_cleanup()],
                    exports=['controller_process_closed', 'controller_material_cleanup',
                             'controller_writer_closed', 'controller_delivery_variables'])
                self.assertEqual(result.returncode, 0 if case in ('fresh', 'bash-fresh') else 2, result.stdout + result.stderr)
                self.assertFalse(facts['controller_writer_closed'])
                self.assertEqual(facts['controller_material_cleanup'], 'retained')
                self.assertEqual(source.read_bytes(), payload)
                self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o400)
                self.assertFalse((record / 'keys').exists())
                self.assertFalse((record / 'gate').exists())
                if case in ('reentry', 'reservation-race'):
                    self.assertFalse(facts['controller_process_closed'])
                    self.assertIsNone(facts['controller_delivery_variables'])
                    self.assertFalse((directory / 'delivery-observed').exists())
                    self.assertFalse((record / 'source').exists())
                    if before is not None:
                        self.assertEqual(record.stat().st_ino, before)
                        self.assertEqual((record / 'marker').read_bytes(), b'existing invocation')
                else:
                    self.assertTrue(facts['controller_process_closed'])
                    self.assertEqual((directory / 'delivery-observed').read_text(), 'journal-before-delivery')
                    children = list((record / 'source').iterdir())
                    self.assertEqual(len(children), 1)
                    self.assertTrue(children[0].name.startswith('opsctl-template-'))
                    self.assertEqual((children[0] / 'playbook.yml').read_bytes(), payload)
                    self.assertFalse(Path(facts['controller_delivery_variables']['path']).exists())
                    self.assertEqual(json.loads((record / 'journal.json').read_text())['phase'], 'reserved')

    def test_frozen_stopped_container_and_policy_deadline_precede_release(self):
        record, journal = self.record_fixture(self.root / 'frozen')
        (record / 'gate').mkdir(mode=0o755)
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
            'Config': {'Labels': {'opsctl.operation': OPERATION, 'opsctl.payload_engine': 'ansible'},
                       'User': str(os.getuid()) + ':' + str(os.getgid()),
                       'Entrypoint': ['/bin/sh', '/run/opsctl-gate/start.sh'],
                       'Cmd': ['/run/opsctl-gate', '/usr/bin/ansible-playbook', '--inventory',
                               '/run/opsctl-keys/inventory.json', '/source/playbook.yml',
                               '--extra-vars', '@/run/opsctl-keys/inputs.json'],
                       'WorkingDir': '/source', 'Healthcheck': {'Test': ['NONE']}},
            'HostConfig': {'NetworkMode': 'selected-network', 'ReadonlyRootfs': True, 'Privileged': False, 'Memory': 67108864,
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
        for case in ['valid', 'identity-drift', 'command-drift', 'policy-failure',
                     'bash-valid', 'bash-network-drift', 'bash-command-drift', 'bash-expired']:
            with self.subTest(case=case):
                bash = case.startswith('bash-')
                self.carrier['payload_engine'] = 'bash' if bash else 'ansible'
                self.carrier['targets'] = [] if bash else [{'address': '192.0.2.3',
                                                          'credential_file': 'synthetic-key'}]
                (record / 'gate/release').unlink(missing_ok=True)
                responses = {'iptables': [{}] * 13, 'systemd-run': [{}],
                             'systemctl': [{'stdout': 'active\n'}, {'stdout': 'active\n'},
                                           {'stdout': '0\n'}, {'stdout': 'active\n'}, {'stdout': '0\n'}],
                             'docker': [{}, {'stdout': CONTAINER + ' ' + OPERATION + ' 123\n'}] * 1
                             + [{'stdout': CONTAINER + ' ' + OPERATION + ' 123\n'}],
                             'nsenter': [{}] * 7 + [{'stdout': '-P OUTPUT DROP\n'}]}
                if case == 'policy-failure':
                    responses['nsenter'][2] = {'rc': 37}
                if bash:
                    responses['docker'].insert(2, {'stdout': 'none|none,'})
                if case == 'bash-expired':
                    responses['systemctl'][2] = {'stdout': '1\n'}
                self.bind_transport(responses)
                container = copy.deepcopy(observed)
                if bash:
                    container['Config'].update(Labels={'opsctl.operation': OPERATION,
                        'opsctl.payload_engine': 'bash'}, Cmd=['/run/opsctl-gate'] + self.payload_argv(),
                        WorkingDir='/workspace/user')
                    container['HostConfig']['NetworkMode'] = 'none'
                    container['NetworkSettings']['Networks'] = {'none': {}}
                if case == 'bash-network-drift':
                    container['HostConfig']['NetworkMode'] = 'bridge'
                if case == 'identity-drift':
                    container['Id'] = 'f' * 64
                if case in ('command-drift', 'bash-command-drift'):
                    container['Config']['Cmd'][-1] = '@/arbitrary.json'
                start = named(self.prepare, 'Start only the trusted gate then install and observe namespace policy under the lock')
                start['ansible.builtin.shell'] = start['ansible.builtin.shell'].replace(
                    '/proc/', str(self.root / 'proc') + '/').replace('/sys/fs/cgroup', str(self.root / 'cgroup'))
                start['environment']['PATH'] = str(self.bin) + ':/usr/sbin:/usr/bin:/sbin:/bin'
                policy = named(self.prepare, 'Install destination policy only for the explicit Ansible engine')
                first = next(index for index, task in enumerate(policy['block'])
                             if task['name'] == 'Create an owned forwarding chain before any container starts')
                policy['block'] = policy['block'][first:]
                tasks = [named(self.execution, "Freeze only the validated engine's native execution bindings"),
                    policy,
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
                    'controller_journal': journal,
                    'controller_source_workspace': str(self.root / 'source'),
                    'controller_network_name': 'selected-network', 'controller_bridge': 'br-selected',
                    'controller_chain': 'OCselected'}, exports=['regression_create_arguments'])
                valid = case in ('valid', 'bash-valid')
                self.assertEqual(result.returncode, 0 if valid else 2, result.stdout + result.stderr)
                args = facts['regression_create_arguments']
                self.assertEqual((args['state'], args['detach'], args['pull']), ('present', True, 'never'))
                self.assertFalse(args['privileged'])
                self.assertTrue(args['read_only'])
                self.assertEqual(args['cap_drop'], ['ALL'])
                self.assertEqual(args['capabilities'], [])
                self.assertEqual(args['memory_swap'], args['memory'])
                self.assertEqual(args['command'], ['/run/opsctl-gate'] + self.payload_argv())
                self.assertEqual(args['entrypoint'], observed['Config']['Entrypoint'])
                self.assertEqual(args['healthcheck'], {'test': ['NONE']})
                self.assertTrue(all(mount['read_only'] for mount in args['mounts']))
                self.assertEqual(sum(int(item.split('size=')[1].split(',')[0]) for item in args['tmpfs'])
                                 + int(args['shm_size']), 1044480)
                calls = self.calls()
                self.assertEqual((record / 'gate/release').exists(), valid)
                if bash:
                    self.assertEqual(args['network_mode'], 'none')
                    self.assertNotIn('networks', args)
                    self.assertEqual(args['mounts'][0]['target'], '/workspace/user')
                    self.assertEqual(args['env'], {'HOME': '/tmp', 'PATH': '/usr/local/bin:/usr/bin:/bin'})
                    self.assertFalse(any(call['tool'] in ('iptables', 'nsenter', 'ip6tables') for call in calls))
                if case in ['identity-drift', 'command-drift', 'bash-network-drift', 'bash-command-drift']:
                    self.assertFalse(any(call['tool'] in ['systemd-run', 'docker', 'nsenter'] for call in calls))
                    continue
                timer = next(index for index, call in enumerate(calls) if call['tool'] == 'systemd-run')
                self.assertIn('deadline', calls[timer]['argv'])
                if case == 'bash-expired':
                    self.assertFalse(any(call['tool'] == 'docker' for call in calls))
                    continue
                start_index = next(index for index, call in enumerate(calls) if call['tool'] == 'docker')
                self.assertLess(timer, start_index)
                self.assertEqual(calls[start_index]['argv'], ['--host', 'unix:///var/run/docker.sock', 'start', CONTAINER])
                if valid:
                    self.assertEqual(stat.S_IMODE((record / 'gate/release').stat().st_mode), 0o444)
                    namespace_calls = [call['argv'] for call in calls if call['tool'] == 'nsenter']
                    self.assertEqual(len(namespace_calls), 0 if bash else 8)
                    self.assertTrue(all('OUTPUT' in args for args in namespace_calls))

    def helper(self, name, gate=None):
        """Bind only unavailable native executable/bind paths, preserving helper logic."""
        body = (CATALOG / ('scripts/user_ansible_controller_' + name + '.sh')).read_text()
        body = body.replace('PATH=/usr/sbin:/usr/bin:/sbin:/bin',
                            'PATH=' + str(self.bin) + ':/usr/sbin:/usr/bin:/sbin:/bin')
        body = body.replace('PATH=/usr/bin:/bin', 'PATH=' + str(self.bin) + ':/usr/bin:/bin')
        body = body.replace('PATH=/usr/local/bin:/usr/bin:/bin',
                            'PATH=' + str(self.bin) + ':/usr/local/bin:/usr/bin:/bin')
        if name == 'start':
            body = body.replace('/run/opsctl-gate', str(gate or self.root / 'gate'))
            body = body.replace('/usr/bin/ansible-playbook', str(self.bin / 'ansible-playbook'))
            body = body.replace('/bin/bash', str(self.bin / 'bash'))
        path = self.root / (name + '.sh')
        path.write_text(body)
        return path

    def test_start_gate_withholds_rejects_closed_and_execs_only_frozen_argv(self):
        gate = self.root / 'gate'
        gate.mkdir(mode=0o755)
        self.bind_transport({'ansible-playbook': [{}]})
        helper = self.helper('start')
        command = ['/bin/sh', str(helper), str(gate), str(self.bin / 'ansible-playbook'),
                   '--inventory', '/run/opsctl-keys/inventory.json', '/source/playbook.yml',
                   '--extra-vars', '@/run/opsctl-keys/inputs.json']
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
        self.assertEqual(payload, [{'tool': 'ansible-playbook', 'argv': command[4:]}])
        for rejected in [command[:3] + ['/bin/sh', 'arbitrary'],
                         command[:-1] + ['@/arbitrary.json'], command + ['extra']]:
            with self.subTest(argv=rejected):
                refused = subprocess.run(rejected, env=self.environment(),
                                         capture_output=True, text=True, timeout=5)
                self.assertEqual(refused.returncode, 64)
        self.assertEqual(len([call for call in self.calls() if call['tool'] == 'ansible-playbook']), 1)

    def test_explicit_engine_refusals_do_not_enter_preallocation_cleanup(self):
        first_include = next(index for index, task in enumerate(self.execution)
                             if 'ansible.builtin.include_tasks' in task)
        validation = self.execution[:first_include]
        accepted = {**self.carrier, 'payload_engine': 'bash', 'targets': [],
                    'staging_directory': str(self.root),
                    'supplied_files': [{'path': 'playbook.yml', 'mode': '0755'}]}
        cleanup = named(self.play['tasks'], 'Prepare run and observe the frozen invocation')['always'][0]
        cleanup.pop('ansible.builtin.include_tasks')
        cleanup['ansible.builtin.set_fact'] = {'regression_cleanup_entered': True}
        for case in ('valid', 'missing', 'unsupported', 'targets', 'mode'):
            with self.subTest(case=case):
                self.carrier = copy.deepcopy(accepted)
                if case == 'missing':
                    del self.carrier['payload_engine']
                elif case == 'unsupported':
                    self.carrier['payload_engine'] = 'python'
                elif case == 'targets':
                    self.carrier['targets'] = [{'address': '192.0.2.3'}]
                elif case == 'mode':
                    self.carrier['supplied_files'][0]['mode'] = '0644'
                result, facts = self.run_tasks(validation, cleanup=[cleanup],
                    exports=['regression_cleanup_entered', 'controller_payload_argv', 'controller_reason'])
                self.assertEqual(result.returncode, 0 if case == 'valid' else 2, result.stdout + result.stderr)
                self.assertIsNone(facts['regression_cleanup_entered'])
                self.assertEqual(facts['controller_reason'], 'invalid_inputs')
                self.assertFalse(list(self.root.glob(OPERATION)))
                if case == 'valid':
                    self.assertEqual(facts['controller_payload_argv'], self.payload_argv())

    def test_bash_gate_withholds_closes_and_preserves_exact_file_argv(self):
        gate = self.root / 'gate'
        gate.mkdir(mode=0o755)
        self.bind_transport({'bash': [{'rc': 37}]})
        helper = self.helper('start')
        command = ['/bin/sh', str(helper), str(gate), str(self.bin / 'bash'),
                   '--noprofile', '--norc', '/workspace/user/main.sh', '/run/opsctl-keys/inputs.json']
        for closed in (True, False):
            with self.subTest(closed=closed):
                (gate / 'closed').unlink(missing_ok=True)
                (gate / 'release').unlink(missing_ok=True)
                process = subprocess.Popen(command, env=self.environment(), stdin=subprocess.DEVNULL,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    time.sleep(0.2)
                    self.assertIsNone(process.poll())
                    self.assertFalse(any(call['tool'] == 'bash' for call in self.calls()))
                    (gate / ('closed' if closed else 'release')).touch(mode=0o444)
                    stdout, stderr = process.communicate(timeout=5)
                    self.assertEqual(process.returncode, 75 if closed else 37, stdout + stderr)
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.communicate()
        self.assertEqual([call for call in self.calls() if call['tool'] == 'bash'],
                         [{'tool': 'bash', 'argv': command[4:]}])
        for rejected in (command + ['extra'], command[:-1] + ['/wrong.json'],
                         command[:4] + ['--login', *command[5:]],
                         command[:6] + ['/workspace/user/../main.sh', command[-1]]):
            with self.subTest(argv=rejected):
                result = subprocess.run(rejected, env=self.environment(), capture_output=True,
                                        text=True, timeout=5)
                self.assertEqual(result.returncode, 64)
        self.assertEqual(len([call for call in self.calls() if call['tool'] == 'bash']), 1)

    def test_private_input_delivery_refusal_and_owned_cleanup(self):
        """Raw native file tasks; root observations and terminal daemon facts modeled."""
        first = next(index for index, task in enumerate(self.prepare)
                     if task['name'] == 'Observe confined frozen credential files before delivery')
        last = next(index for index, task in enumerate(self.prepare)
                    if task['name'] == 'Write immutable inventory using only central target facts')
        values = {'literal': {'value': '${HOME} {{ literal }} $HOME'},
                  'unicode': {'value': '\u00e9\u96ea'}, 'empty': {},
                  'nested': {'values': [None, False, 0, '', {'child': ['x', []]}],
                             'ansible_host': 'application-host',
                             'ansible_user': 'application-user',
                             'ansible_ssh_private_key_file': '/application/key'}}
        cases = [*values, 'missing', 'digest', 'mode', 'symlink', 'size', 'count', 'total', 'failure', 'bash-input']
        for case in cases:
            with self.subTest(case=case):
                self.carrier['payload_engine'] = 'bash' if case == 'bash-input' else 'ansible'
                root = self.root / case
                stage = root / 'staged'
                stage.mkdir(mode=0o700, parents=True)
                record, journal = self.record_fixture(root)
                (record / 'keys').mkdir(mode=0o700)
                observed_keys = (record / 'keys').stat()
                journal['private_identities']['keys'] = {
                    'dev': observed_keys.st_dev, 'inode': observed_keys.st_ino,
                    'uid': os.getuid(), 'mode': '0700'}
                workspace = record / 'source/opsctl-template-fixture'
                workspace.mkdir(mode=0o700)
                payload = json.dumps({'opsctl_inputs': values.get(case, values['nested'])},
                                     ensure_ascii=False,
                                     sort_keys=True, separators=(',', ':')).encode('utf-8')
                if case == 'size':
                    payload = b'x' * 262145
                original = stage / 'template-inputs.json'
                if case != 'missing':
                    original.write_bytes(payload)
                    original.chmod(0o644 if case == 'mode' else 0o600)
                    if case == 'symlink':
                        original.rename(stage / 'original')
                        original.symlink_to('original')
                originals = {}
                keys = []
                for index in range(0 if case == 'bash-input' else 8 if case == 'count' else 1):
                    key = stage / ('key-' + str(index))
                    key.write_bytes(b'private synthetic credential')
                    key.chmod(0o600)
                    originals[key] = (key.read_bytes(), 0o600)
                    keys.append({'credential_file': key.name})
                sources = []
                for index in range(32 if case == 'count' else 3 if case == 'total' else 1):
                    source = stage / ('source-%02d' % index)
                    source.write_bytes(b'x' * 262144 if case == 'total' else b'synthetic source not executed')
                    source.chmod(0o600)
                    originals[source] = (source.read_bytes(), 0o600)
                    sources.append({'source': source.name, 'path': source.name, 'mode': '0600',
                                    'size_bytes': source.stat().st_size,
                                    'sha256': hashlib.sha256(source.read_bytes()).hexdigest()})
                    (workspace / source.name).write_bytes(source.read_bytes())
                self.carrier.update(staging_directory=str(stage), supplied_files=sources,
                                    targets=keys, input_digest='0' * 64 if case == 'digest'
                                    else hashlib.sha256(payload).hexdigest())
                result, facts = self.run_tasks([
                    named(self.execution, "Freeze only the validated engine's native execution bindings"),
                    *copy.deepcopy(self.prepare[first:last])], {
                    'controller_record': str(record)}, exports=['controller_delivered_input'])
                valid = case in values or case in ('failure', 'bash-input')
                self.assertEqual(result.returncode, 0 if valid else 2, result.stdout + result.stderr)
                delivered = record / 'keys/inputs.json'
                if valid:
                    self.assertEqual(delivered.read_bytes(), payload)
                    self.assertEqual(stat.S_IMODE(delivered.stat().st_mode), 0o600)
                    self.assertEqual((delivered.stat().st_uid, delivered.stat().st_gid),
                                     (os.getuid(), os.getgid()))
                    self.assertEqual(facts['controller_delivered_input']['stat']['checksum'],
                                     self.carrier['input_digest'])
                    self.assertNotIn(payload.decode('utf-8'), result.stdout + result.stderr)
                    if case == 'bash-input':
                        self.assertEqual([path.name for path in (record / 'keys').iterdir()], ['inputs.json'])
                else:
                    self.assertFalse(delivered.exists())
                    self.assertEqual(list((record / 'keys').iterdir()), [])
                if case == 'failure':
                    gate = self.root / 'gate'
                    gate.mkdir(mode=0o755)
                    (gate / 'release').touch(mode=0o444)
                    self.bind_transport({'ansible-playbook': [{'rc': 37}]})
                    helper = self.helper('start')
                    command = ['/bin/sh', str(helper), str(gate), str(self.bin / 'ansible-playbook'),
                               '--inventory', '/run/opsctl-keys/inventory.json', '/source/playbook.yml',
                               '--extra-vars', '@/run/opsctl-keys/inputs.json']
                    terminal = subprocess.run(command, env=self.environment(),
                                              capture_output=True, text=True, timeout=5)
                    self.assertEqual(terminal.returncode, 37, terminal.stdout + terminal.stderr)
                    (self.bin / 'ansible-playbook').unlink()
                    closure = self.private_cleanup()
                    result, facts = self.run_tasks([
                        named(self.execution, 'Retain actual exit status independently of logs'),
                        closure], {'controller_record': str(record), 'controller_record_owned': True,
                                   'controller_journal': journal, 'controller_writer_closed': True,
                                   'controller_cleanup_uid': os.getuid(),
                                   'controller_cleanup_operation': OPERATION,
                                   'controller_original_closure': {'stdout': 'process_closed:exited:stopped'},
                                   'controller_record_identity': self.source_identity(record),
                                   'controller_source_workspace': str(workspace),
                                   'controller_source_identity': self.source_identity(workspace),
                                   'controller_terminal': {'container': {'State': {'ExitCode': terminal.returncode}}},
                                   'controller_original_reason': 'execution_failed'},
                        exports=['controller_material_cleanup', 'controller_process_closed',
                                 'controller_reason', 'controller_original_reason', 'controller_exit_code'])
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(facts['controller_exit_code'], 37)
                    self.assertEqual(facts['controller_reason'], 'execution_failed')
                    self.assertEqual(facts['controller_original_reason'], 'execution_failed')
                    self.assertTrue(facts['controller_process_closed'])
                    self.assertEqual(facts['controller_material_cleanup'], 'removed')
                    self.assertFalse(delivered.exists())
                    self.assertFalse(workspace.exists())
                for path, (data, mode) in originals.items():
                    self.assertEqual(path.read_bytes(), data)
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)
                if case != 'missing':
                    self.assertEqual(original.read_bytes(), payload)
                self.assertNotIn('private synthetic credential', result.stdout + result.stderr)
        self.carrier.update(controller_server_id='00000000-0000-4000-8000-000000000002')
        self.carrier['payload_engine'] = 'ansible'
        for reserved in ['template-inputs.json', 'inputs.json']:
            with self.subTest(credential=reserved):
                self.carrier['targets'] = [{
                    'server_id': '00000000-0000-4000-8000-000000000003',
                    'ssh_access_key_id': '00000000-0000-4000-8000-000000000004',
                    'credential_secret_id': '00000000-0000-4000-8000-000000000005',
                    'credential_version': 1, 'port': 22, 'address': '192.0.2.3',
                    'username': 'opsctl', 'host_public_key': 'ssh-ed25519 AAAA',
                    'credential_file': reserved}]
                result, _ = self.run_tasks([
                    named(self.execution, 'Require exact safe target facts from central preparation')])
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_private_lock_creation_and_historical_witness_confinement(self):
        bodies = {
            'prepare': named(walk(self.prepare), 'Start only the trusted gate then install and observe namespace policy under the lock')['ansible.builtin.shell'],
            'close': None,
            'refresh': named(walk(self.recovery), 'Refresh current trusted close code only for qualified original settlement')['ansible.builtin.shell'],
            'material': named(walk(self.cleanup), 'Release private material only under the exact completed-writer closure lock')['ansible.builtin.shell'],
            'journal': named(walk(self.cleanup), 'Atomically persist settlement only if the original journal is unchanged')['ansible.builtin.shell'],
        }
        identity = ' '.join([CONTAINER, OPERATION, self.carrier['source_digest'],
                             self.carrier['input_digest']]) + ' false 0\n'
        sentinel_before = (self.sentinel.read_bytes(), self.sentinel.stat().st_ino,
                           stat.S_IMODE(self.sentinel.stat().st_mode))
        for consumer, body in bodies.items():
            cases = ('new',) if consumer == 'prepare' else (
                '0600', '0644', 'linked', 'hardlinked', 'writable', 'unowned', 'nonempty')
            for case in cases:
                with self.subTest(consumer=consumer, case=case):
                    self.bind_transport({'docker': [{'stdout': identity}] * 2,
                                         'systemctl': [{'rc': 19}]})
                    record = self.root / (consumer + '-' + case)
                    record.mkdir(mode=0o700)
                    history = b'{"writer_closed":false,"outcome":"unknown"}'
                    helper_bytes = (CATALOG / 'scripts/user_ansible_controller_close.sh').read_text()
                    files = {'container-id': CONTAINER + '\n',
                             'source-digest': self.carrier['source_digest'] + '\n',
                             'input-digest': self.carrier['input_digest'] + '\n',
                             'journal.json': history.decode(), 'writer-closed': '',
                             'close.sh': helper_bytes}
                    if consumer != 'prepare':
                        files['closed'] = ''
                    for name, content in files.items():
                        path = record / name
                        path.write_text(content)
                        path.chmod(0o700 if name == 'close.sh' else 0o600)
                    for name in ('source', 'keys', 'gate'):
                        (record / name).mkdir(mode=0o700)
                    lock = record / 'lock'
                    if case == 'linked':
                        lock.symlink_to(self.sentinel)
                    elif case == 'hardlinked':
                        os.link(self.sentinel, lock)
                    elif case != 'new':
                        lock.write_text('retained witness' if case == 'nonempty' else '')
                        lock.chmod(0o644 if case == '0644' else 0o664 if case == 'writable' else 0o600)
                    before = None if case == 'new' else (lock.lstat().st_ino, lock.lstat().st_mode)
                    observed = record.stat()
                    env = {**self.environment(), 'RECORD': str(record),
                           'DEVICE': str(observed.st_dev), 'INODE': str(observed.st_ino),
                           'EXPECTED': hashlib.sha256(history).hexdigest(), 'JOURNAL': history.decode(),
                           'HELPER': helper_bytes, 'EFFECT_FENCED': 'false', 'UNIT': 'owned-fixture'}
                    if case == 'unowned':
                        env['CONTROLLER_FOREIGN_LOCK'] = str(lock)
                    command = ['/bin/sh', str(self.helper('close')), '--bounded', str(record), OPERATION, 'normal'] if consumer == 'close' else [
                        '/bin/sh', '-c', 'umask 022\n' + body]
                    result = subprocess.run(command, env=env, stdin=subprocess.DEVNULL,
                                            capture_output=True, text=True, timeout=40)
                    expected = 19 if consumer == 'prepare' else 0 if case in ('0600', '0644') else 1 if case == 'linked' and consumer != 'close' else 65
                    self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                    self.assertEqual((self.sentinel.read_bytes(), self.sentinel.stat().st_ino,
                                      stat.S_IMODE(self.sentinel.stat().st_mode)), sentinel_before)
                    self.assertEqual((record / 'journal.json').read_bytes(), history)
                    if before is None:
                        self.assertEqual(stat.S_IMODE(lock.stat().st_mode), 0o600)
                        self.assertEqual(lock.stat().st_size, 0)
                    else:
                        self.assertEqual((lock.lstat().st_ino, lock.lstat().st_mode), before)
                    if consumer == 'material':
                        for name in ('source', 'keys', 'gate'):
                            self.assertEqual((record / name).exists(), case not in ('0600', '0644'))
                    if case not in ('new', '0600', '0644'):
                        self.assertFalse(any(call['tool'] not in ('stat', 'flock') for call in self.calls()))

    def test_close_decisions_distinguish_deadline_late_exit_exact_absence_and_uncertainty(self):
        identity = ' '.join([CONTAINER, OPERATION, self.carrier['source_digest'], self.carrier['input_digest']])
        stopped = identity + ' false 0\n'
        running = identity + ' true 123\n'
        cases = {
            'ordinary': ('normal', [{'stdout': stopped}] * 2, 0, 'exited:stopped'),
            'deadline': ('deadline', [{'stdout': running}, {}, {'stdout': stopped}, {'stdout': stopped}], 0, 'deadline:stopped'),
            'late-timer': ('deadline', [{'stdout': stopped}] * 2, 0, 'exited:stopped'),
            'absent': ('normal', [{'rc': 1}, {}, {'rc': 1}, {}], 0, 'absent:absent'),
            'unknown': ('normal', [{'rc': 1}, {'rc': 37}], 70, None),
            'foreign': ('normal', [{'stdout': 'f' * 64 + identity[64:] + ' true 123\n'}], 65, None),
        }
        for case, (cause, responses, expected_rc, decision) in cases.items():
            with self.subTest(case=case):
                record = self.root / case
                record.mkdir(mode=0o700)
                (record / 'container-id').write_text(CONTAINER + '\n')
                (record / 'container-id').chmod(0o600)
                for name in ('source', 'input'):
                    (record / (name + '-digest')).write_text(self.carrier[name + '_digest'] + '\n')
                    (record / (name + '-digest')).chmod(0o600)
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
        for case in ['bounded', 'failed', 'term-ignored', 'unknown-process', 'success-log-failed', 'success-cleanup-failed']:
            with self.subTest(case=case):
                record, journal = self.record_fixture(self.root / case)
                workspace = record / 'source/opsctl-template-fixture'
                workspace.mkdir(mode=0o700)
                delivered = workspace / 'playbook.yml'
                delivered.write_bytes(original.read_bytes())
                delivered.chmod(0o600)
                response = {'stdout': 'safe-output-' + 'é' * 200}
                if case in ('failed', 'success-log-failed'):
                    response = {'rc': 37}
                if case == 'success-cleanup-failed':
                    (record / 'keys').symlink_to(self.root)
                if case == 'term-ignored':
                    response = {'ignore_term': True, 'sleep': 30}
                self.bind_transport({'docker': [response]})
                logs = named(self.cleanup, 'Collect bounded logs independently of safe liability cleanup')
                logs['block'][0]['environment']['PATH'] = str(self.bin) + ':/usr/sbin:/usr/bin:/sbin:/bin'
                closure = self.private_cleanup()
                closure['rescue'].append({'ansible.builtin.set_fact': {
                    'regression_cleanup_task': '{{ ansible_failed_task.name }}',
                    'regression_cleanup_rc': '{{ ansible_failed_result.rc | default(none) }}'}})
                started = time.monotonic()
                result, facts = self.run_tasks([logs, closure], {
                    'controller_record': str(record), 'controller_record_owned': True,
                    'controller_record_identity': self.source_identity(record),
                    'controller_journal': journal, 'controller_writer_closed': True,
                    'controller_cleanup_uid': os.getuid(), 'controller_cleanup_operation': OPERATION,
                    'controller_log_budget': 128, 'controller_execution_known': True,
                    'controller_source_workspace': str(workspace),
                    'controller_source_identity': self.source_identity(workspace),
                    'controller_container_id': CONTAINER, 'controller_close_presence': 'stopped',
                    'controller_process_closed': case != 'unknown-process',
                    'controller_material_cleanup': 'retained',
                    'controller_original_reason': None if case.startswith('success') else 'execution_failed',
                    'controller_reason': 'exited' if case.startswith('success') else 'execution_failed',
                    'controller_outcome': 'succeeded' if case.startswith('success') else 'failed'},
                    exports=['controller_original_reason', 'controller_reason', 'controller_logs',
                             'controller_logs_truncated', 'controller_material_cleanup', 'controller_outcome',
                             'regression_cleanup_task', 'regression_cleanup_rc'])
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(original.read_bytes(), b'unchanged source bytes')
                self.assertEqual(facts['controller_outcome'], 'succeeded' if case.startswith('success') else 'failed')
                self.assertEqual(facts['controller_original_reason'],
                                 'log_collection_failed' if case == 'success-log-failed' else
                                 'cleanup_failed' if case == 'success-cleanup-failed' else 'execution_failed')
                self.assertLessEqual(len(facts['controller_logs'].encode('utf-8')), 128)
                self.assertNotIn('unchanged source bytes', result.stdout + result.stderr)
                if case == 'unknown-process':
                    self.assertTrue(workspace.exists())
                    self.assertEqual(facts['controller_material_cleanup'], 'retained')
                    self.assertEqual(self.calls(), [])
                elif case == 'success-cleanup-failed':
                    self.assertTrue(workspace.exists())
                    self.assertEqual(facts['controller_material_cleanup'], 'retained')
                    self.assertEqual(facts['controller_reason'], 'cleanup_failed')
                    self.assertTrue((record / 'keys').is_symlink())
                else:
                    self.assertFalse(workspace.exists(), json.dumps(facts) + result.stdout + result.stderr)
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
    if sys.argv[1:2] == ['--delivery']:
        sys.exit(delivery_transport())
    unittest.main()
