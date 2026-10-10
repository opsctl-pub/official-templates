"""Loaded production setup with explicit host/daemon transports, no live socket."""

import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

import yaml


PLAYBOOK = Path(__file__).resolve().parents[1] / 'catalog/ansible/playbooks/template_runtime_setup.yml'
UUID = '00000000-0000-4000-8000-000000000001'
BACKEND_PREFIX = 'Runtime backend observation: '
BACKEND_KEYS = {'server_version', 'firewall_backend_present', 'driver_string_present',
                'driver', 'docker_user_read_succeeded'}


class TemplateRuntimeSetupTests(unittest.TestCase):
    def invoke(self, case, expected, daemon_overrides=None, chain_rc=0,
               progress_expected=None, backend_expected=None):
        """Keep production qualification/emission and the real GNU deadline."""
        with tempfile.TemporaryDirectory(prefix='runtime-setup-') as temporary:
            directory = Path(temporary)
            play = yaml.safe_load(PLAYBOOK.read_text())
            owner = play[0]
            self.assertFalse(owner['become'])
            self.assertEqual(owner['module_defaults']['group/community.docker.docker'], {
                'docker_host': 'unix:///var/run/docker.sock', 'api_version': 'auto',
                'tls': False, 'validate_certs': False, 'timeout': 10,
            })
            image_name = owner['vars']['runtime_image']
            profile = owner['vars']['runtime_profile']
            image = {'Id': 'sha256:' + 'a' * 64, 'RepoDigests': [image_name],
                     'Os': 'linux', 'Architecture': 'amd64', 'Config': {'Volumes': None}}
            daemon = {'ID': 'synthetic-local-daemon', 'ServerVersion': '29.8.0',
                      'OSType': 'linux', 'SecurityOptions': ['name=seccomp'],
                      'FirewallBackend': {'Driver': 'iptables'}, 'CgroupVersion': '2',
                      'CgroupDriver': 'systemd', 'MemoryLimit': True, 'SwapLimit': True,
                      'CpuCfsQuota': True, 'CpuCfsPeriod': True, 'PidsLimit': True}
            if case == 'unknown-backend':
                daemon.pop('FirewallBackend')
            if case == 'nft-backend':
                daemon['FirewallBackend']['Driver'] = 'nftables'
            if case == 'unknown-version':
                daemon['ServerVersion'] = '99.0.0'
            if daemon_overrides:
                daemon.update(daemon_overrides)
            if case == 'rootless':
                daemon['SecurityOptions'].append('name=rootless')
            if case == 'digest':
                image['RepoDigests'] = ['PRIVATE_FOREIGN_DIGEST']
            if case == 'platform':
                image['Architecture'] = 'arm64'
            if case == 'volumes':
                image['Config']['Volumes'] = {'/PRIVATE_VOLUME': {}}
            library = directory / 'library'
            library.mkdir()
            (library / 'runtime_failure.py').write_text(
                'from ansible.module_utils.basic import AnsibleModule\n'
                'm = AnsibleModule(argument_spec={})\n'
                'm.fail_json(msg="PRIVATE_MODULE_FAILURE")\n')
            tasks = owner['tasks'][1]['block']
            for task in tasks:
                name = task['name']
                command = task.get('ansible.builtin.command')
                if command:
                    self.assertFalse(command['expand_argument_vars'])
                    self.assertEqual(command['stdin'], '')
                    self.assertEqual((task['async'], task['poll']), (30, 1))
                    self.assertTrue(task['no_log'])
                if name == 'Read actual management UID without escalation':
                    self.assertEqual(command['argv'], ['/usr/bin/timeout', '--signal=KILL', '10', 'id', '-u'])
                    command['argv'][3:] = ['/bin/echo', '1000' if case == 'nonroot' else '0']
                if name == 'Read only fixed bounded host prerequisites':
                    self.assertEqual(command['argv'], "{{ ['/usr/bin/timeout', '--signal=KILL', '10'] + item.argv }}")
                    values = {'linux': 'Linux', 'pid1': '/usr/lib/systemd/systemd',
                              'systemd': 'active', 'controllers': 'cpu memory pids',
                              'flock': '--exclusive --timeout',
                              'systemd_run': '--on-active --timer-property', 'iconv': '-c',
                              'iptables': '--wait', 'ip6tables': '--wait',
                              'nsenter': '--net', 'docker': 'Docker CLI', 'docker_user': 'readable'}
                    if case == 'tools':
                        values['flock'] = 'unsupported options'
                    if case == 'controllers':
                        values['controllers'] = 'cpu pids'
                    for item in task['loop']:
                        item['argv'] = ['/bin/echo', values[item['key']]]
                        if item['key'] == 'docker_user' and chain_rc != 0:
                            item['argv'] = ['/bin/sh', '-c', 'exit "$1"', 'chain-read', str(chain_rc)]
                        if case == 'timeout' and item['key'] == 'flock':
                            item['argv'] = ['/bin/sh', '-c',
                                'echo $$ > "' + str(directory / 'pid') + '"; sleep 30']
                    # Only loop management polling is modeled; native timeout stays real.
                    task.pop('async')
                    task.pop('poll')
                for module in ('community.docker.docker_host_info',
                               'community.docker.docker_image_info',
                               'community.docker.docker_image_pull'):
                    if module not in task:
                        continue
                    arguments = task.pop(module)
                    registration = task.pop('register')
                    self.assertTrue(task['no_log'])
                    self.assertFalse(task['failed_when'])
                    if module.endswith('docker_host_info'):
                        self.assertEqual(arguments, dict.fromkeys(
                            ('containers', 'images', 'networks', 'volumes', 'disk_usage'), False))
                        observation = copy.deepcopy(daemon)
                        if case == 'changed-daemon' and registration == 'runtime_final_daemon':
                            observation['ID'] = 'replacement'
                        if case == 'changed-backend' and registration == 'runtime_final_daemon':
                            observation['FirewallBackend'] = {'Driver': 'nftables'}
                        task['ansible.builtin.set_fact'] = {registration: {'host_info': observation}}
                    elif module.endswith('docker_image_info'):
                        self.assertEqual(arguments, {'name': '{{ runtime_image }}'})
                        missing = case == 'missing' or (case == 'prepare-missing' and registration == 'runtime_inspection')
                        task['ansible.builtin.set_fact'] = {
                            registration: {'images': [] if missing else [image]},
                            'test_inspections': "{{ (test_inspections | default([])) + ['" + registration + "'] }}",
                        }
                    else:
                        self.assertEqual(arguments, {'name': '{{ runtime_image }}',
                            'platform': 'linux/amd64', 'pull': 'not_present'})
                        task['ansible.builtin.set_fact'] = {
                            registration: {'image': image}, 'test_pull': True,
                        }
                    if ((case == 'daemon-failure' and registration == 'runtime_daemon') or
                            (case == 'pull-failure' and registration == 'runtime_pull')):
                        task.pop('ansible.builtin.set_fact')
                        task['runtime_failure'] = {}
                        task['register'] = registration
                    else:
                        task['ansible.builtin.set_fact']['test_module_calls'] = (
                            "{{ test_module_calls | default([]) + [" + repr(name) + "] }}")
            owner['tasks'].insert(-1, {'name': 'Safe test transport observations',
                'ansible.builtin.debug': {'msg': "{{ {'pull': test_pull | default(false), 'inspections': test_inspections | default([]), 'calls': test_module_calls | default([])} | to_json }}"}})
            carrier = {'operation_id': UUID, 'server_id': UUID,
                       'action': 'prepare' if case.startswith('prepare-') or case == 'pull-failure' else 'verify',
                       'profile': profile, 'image': image_name}
            if case == 'extra':
                carrier['unexpected'] = 'PRIVATE_INPUT'
            if case == 'profile':
                carrier['profile'] = 'PRIVATE_PROFILE'
            if case == 'uuid':
                carrier['operation_id'] += '\n'
            invocation = directory / 'play.yml'
            invocation.write_text(yaml.safe_dump(play, sort_keys=False))
            inputs = directory / 'inputs.json'
            inputs.write_text(json.dumps({'template_runtime_setup': carrier,
                                         'ansible_async_dir': str(directory / 'async')}))
            started = time.monotonic()
            result = subprocess.run(['ansible-playbook', '-i', '127.0.0.1,', '-c', 'local',
                str(invocation), '-e', '@' + str(inputs)], capture_output=True, text=True, timeout=75,
                env={**os.environ, 'HOME': str(directory), 'ANSIBLE_NOCOLOR': '1',
                     'ANSIBLE_LIBRARY': str(library), 'ANSIBLE_STDOUT_CALLBACK': 'default',
                     'ANSIBLE_LOCAL_TEMP': str(directory / 'local'),
                     'ANSIBLE_REMOTE_TEMP': str(directory / 'remote')})
            output = result.stdout + result.stderr
            self.assertEqual(result.returncode, 0, output)
            self.assertNotIn('PRIVATE_', output)
            messages = []
            progress = []
            effects = None
            for line in result.stdout.splitlines():
                if '"msg": ' not in line:
                    continue
                message = json.JSONDecoder().raw_decode(line.split('"msg": ', 1)[1])[0]
                if isinstance(message, str) and message.startswith('TEMPLATE_OUTPUT_JSON='):
                    self.assertTrue(message.isascii())
                    self.assertLessEqual(len(message.encode('ascii')) + 1, 16384)
                    envelope = json.loads(message.split('=', 1)[1])
                    self.assertEqual(set(envelope), {'template_runtime_setup_result'})
                    messages.append(envelope['template_runtime_setup_result'])
                elif isinstance(message, str) and message.startswith('{"pull":'):
                    effects = json.loads(message)
                elif isinstance(message, str) and message.startswith(BACKEND_PREFIX):
                    self.assertTrue(message.isascii())
                    self.assertLessEqual(len(message.encode('ascii')) + 1, 1024)
                    progress.append(json.loads(message[len(BACKEND_PREFIX):]))
            self.assertEqual(len(messages), 1, output)
            report = messages[0]
            self.assertEqual(set(report), {'operation_id', 'server_id', 'action', 'profile',
                'image', 'outcome', 'reason', 'observed_at', 'checks'})
            self.assertEqual(set(report['checks']), {'management_root', 'linux', 'systemd',
                'rootful_docker', 'iptables_backend', 'cgroup_v2', 'required_tools',
                'image_present', 'image_compatible'})
            self.assertTrue(all(type(value) is bool or value is None for value in report['checks'].values()))
            self.assertRegex(report['observed_at'], r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')
            self.assertEqual((report['outcome'], report['reason']), expected, output)
            self.assertEqual(effects['pull'], case in ('prepare-missing', 'prepare-present'))
            if case.startswith('prepare-'):
                self.assertEqual(effects['inspections'], ['runtime_inspection', 'runtime_prepared'])
            if case in ('extra', 'uuid', 'profile'):
                self.assertIsNone(report['operation_id'])
                self.assertTrue(all(value is None for value in report['checks'].values()))
                self.assertEqual(effects['inspections'], [])
            if report['outcome'] == 'eligible':
                self.assertTrue(all(value is True for value in report['checks'].values()))
            if case in ('unknown-backend', 'changed-daemon', 'changed-backend'):
                self.assertIsNone(report['checks']['iptables_backend'])
            if progress_expected is not None:
                self.assertEqual(len(progress), 1, output)
                self.assertEqual(set(progress[0]), BACKEND_KEYS)
                self.assertEqual(progress[0], progress_expected)
                self.assertTrue(all(type(progress[0][key]) is bool for key in
                    ('firewall_backend_present', 'driver_string_present', 'docker_user_read_succeeded')))
            if case == 'direct-refusal':
                self.assertIs(report['checks']['iptables_backend'], backend_expected)
                self.assertIsNone(report['checks']['image_present'])
                self.assertIsNone(report['checks']['image_compatible'])
                self.assertEqual(effects['calls'], [
                    'Observe this local daemon without unrelated object enumeration'])
            if report['outcome'] == 'eligible' or case in ('changed-daemon', 'changed-backend'):
                if carrier['action'] == 'verify':
                    self.assertEqual(effects['calls'], [
                        'Observe this local daemon without unrelated object enumeration',
                        'Inspect only the fixed local image',
                        'Reobserve the same local daemon before eligibility'])
            if case == 'pull-failure':
                self.assertTrue(report['checks']['image_present'])
                self.assertIsNone(report['checks']['image_compatible'])
            if case == 'timeout':
                self.assertLess(time.monotonic() - started, 60)
                pid = int((directory / 'pid').read_text())
                status = Path('/proc') / str(pid) / 'stat'
                state = status.read_text().split(') ', 1)[1].split()[0] if status.exists() else None
                self.assertIn(state, (None, 'Z', 'X'), 'owned sleeper still running')

    def test_closed_carrier_and_root_refuse_before_image_effects(self):
        for case in ('extra', 'uuid', 'profile', 'nonroot'):
            with self.subTest(case=case):
                self.invoke(case, ('unsupported', 'management_unavailable' if case == 'nonroot' else 'invalid_inputs'))

    def test_backend_tools_and_changed_daemon_preserve_uncertainty(self):
        for case in ('unknown-backend', 'nft-backend', 'unknown-version', 'rootless',
                     'tools', 'controllers', 'changed-daemon'):
            with self.subTest(case=case):
                expected = ('unsupported', 'management_unavailable' if case == 'changed-daemon' else 'unsupported_profile')
                if case == 'unknown-version':
                    expected = ('eligible', 'ready')
                self.invoke(case, expected)

    def test_direct_backend_identity_driver_and_progress_refuse_before_images(self):
        for overrides, chain_rc, expected, present, string_present, driver in (
            ({'ID': None}, 0, None, True, True, 'iptables'),
            ({'ID': 17}, 0, None, True, True, 'iptables'),
            ({'ID': ''}, 0, None, True, True, 'iptables'),
            ({'FirewallBackend': None}, 0, None, True, False, None),
            ({'FirewallBackend': ['PRIVATE_BACKEND']}, 0, None, True, False, None),
            ({'FirewallBackend': {}}, 0, None, True, False, None),
            ({'FirewallBackend': {'Driver': False}}, 0, None, True, False, None),
            ({'FirewallBackend': {'Driver': ''}}, 0, None, True, False, None),
            ({'FirewallBackend': {'Driver': 'iptables+firewalld'}}, 0, None, True, True, None),
            ({'FirewallBackend': {'Driver': 'PRIVATE_DRIVER'}}, 0, None, True, True, None),
            ({'FirewallBackend': {'Driver': 'nftables'}}, 0, False, True, True, 'nftables'),
            ({}, 2, False, True, True, 'iptables'),
        ):
            with self.subTest(overrides=overrides, chain_rc=chain_rc):
                self.invoke('direct-refusal', ('unsupported', 'unsupported_profile'),
                    daemon_overrides=overrides, chain_rc=chain_rc, backend_expected=expected,
                    progress_expected={'server_version': '29.8.0',
                        'firewall_backend_present': present, 'driver_string_present': string_present,
                        'driver': driver, 'docker_user_read_succeeded': chain_rc == 0})
        self.invoke('unknown-backend', ('unsupported', 'unsupported_profile'),
            progress_expected={'server_version': '29.8.0', 'firewall_backend_present': False,
                'driver_string_present': False, 'driver': None, 'docker_user_read_succeeded': True})

    def test_backend_progress_sanitizes_versions_without_granting_eligibility(self):
        for version, public in (
            ('28.5.1', '28.5.1'),
            (None, None),
            (False, None),
            (['PRIVATE_VERSION'], None),
            ('PRIVATE_VERSION', None),
            ('28.5.1\nPRIVATE_VERSION', None),
            ('28.5.1-\u00e9', None),
            ('28.5.1-' + 'a' * 57, '28.5.1-' + 'a' * 57),
            ('28.5.1-' + 'a' * 58, None),
        ):
            with self.subTest(version=version):
                self.invoke('direct-refusal', ('unsupported', 'unsupported_profile'),
                    daemon_overrides={'ServerVersion': version, 'FirewallBackend': None},
                    progress_expected={'server_version': public, 'firewall_backend_present': True,
                        'driver_string_present': False, 'driver': None,
                        'docker_user_read_succeeded': True})
        self.invoke('changed-backend', ('unsupported', 'management_unavailable'))

    def test_backend_progress_exact_wire_guard_and_safe_fallback(self):
        owner = yaml.safe_load(PLAYBOOK.read_text())[0]
        tasks = owner['tasks'][1]['block']
        block = next(task for task in tasks
                     if task['name'] == 'Prepare one bounded safe backend progress observation')
        emit = next(task for task in tasks if task['name'] == 'Emit one safe backend progress observation')
        fallback = {'server_version': None, 'firewall_backend_present': False,
                    'driver_string_present': False, 'driver': None,
                    'docker_user_read_succeeded': False}
        for size in (1024, 1025):
            with self.subTest(size=size), tempfile.TemporaryDirectory() as temporary:
                # Inject only stored wire to exercise the actual guard/rescue, not
                # the semantic projection or its naturally much smaller output.
                wire = json.dumps(fallback)
                wire += ' ' * (size - len(BACKEND_PREFIX) - 1 - len(wire))
                guard = copy.deepcopy(block)
                guard['block'] = guard['block'][1:]
                play = [{'hosts': 'all', 'gather_facts': False,
                         'vars': {'runtime_backend_wire': wire}, 'tasks': [guard, emit]}]
                directory = Path(temporary)
                path = directory / 'play.yml'
                path.write_text(yaml.safe_dump(play, sort_keys=False))
                result = subprocess.run(['ansible-playbook', '-i', '127.0.0.1,', '-c', 'local', str(path)],
                    capture_output=True, text=True, timeout=30,
                    env={**os.environ, 'HOME': temporary, 'ANSIBLE_NOCOLOR': '1',
                         'ANSIBLE_STDOUT_CALLBACK': 'default',
                         'ANSIBLE_LOCAL_TEMP': str(directory / 'local'),
                         'ANSIBLE_REMOTE_TEMP': str(directory / 'remote')})
                output = result.stdout + result.stderr
                self.assertEqual(result.returncode, 0, output)
                messages = []
                for line in result.stdout.splitlines():
                    if '"msg": ' in line:
                        value = json.JSONDecoder().raw_decode(line.split('"msg": ', 1)[1])[0]
                        if isinstance(value, str) and value.startswith(BACKEND_PREFIX):
                            messages.append(value)
                self.assertEqual(len(messages), 1, output)
                self.assertTrue(messages[0].isascii())
                self.assertLessEqual(len(messages[0].encode('ascii')) + 1, 1024)
                self.assertEqual(json.loads(messages[0][len(BACKEND_PREFIX):]), fallback)
                if size == 1024:
                    self.assertEqual(messages[0], BACKEND_PREFIX + wire)
                else:
                    self.assertEqual(messages[0], BACKEND_PREFIX + json.dumps(fallback))

    def test_verify_and_exact_prepare_reinspection_and_compatibility(self):
        for case in ('verify', 'prepare-missing', 'prepare-present', 'missing',
                     'digest', 'platform', 'volumes'):
            with self.subTest(case=case):
                expected = ('eligible', 'ready')
                if case == 'missing':
                    expected = ('unsupported', 'image_unavailable')
                if case in ('digest', 'platform', 'volumes'):
                    expected = ('unsupported', 'image_incompatible')
                self.invoke(case, expected)

    def test_private_failures_and_real_native_deadline_have_one_safe_result(self):
        for case, expected in (
            ('daemon-failure', ('unsupported', 'management_unavailable')),
            ('pull-failure', ('failed', 'setup_failed')),
            ('timeout', ('unsupported', 'unsupported_profile')),
        ):
            with self.subTest(case=case):
                self.invoke(case, expected)


if __name__ == '__main__':
    unittest.main()
