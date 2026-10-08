"""Offline native-task contracts with a fake Docker transport, never a daemon."""

import base64
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

import yaml


CATALOG = Path(__file__).resolve().parents[1] / 'catalog/ansible'


def named(tasks, name):
    """Find an actual named task through its native control-flow sections."""
    for task in tasks:
        if task.get('name') == name:
            return task
        for section in ('tasks', 'block', 'rescue', 'always'):
            result = named(task.get(section, []), name)
            if result is not None:
                return result
    return None


def response(value='', code=0, **options):
    """Describe a synthetic Docker response, optionally containing raw bytes."""
    output = value if isinstance(value, (str, bytes)) else json.dumps(value)
    if isinstance(output, bytes):
        output = base64.b64encode(output).decode('ascii')
        options['base64'] = True
    return {'stdout': output, 'rc': code, **options}


def run_tasks(tasks, variables, responses, timeout=90):
    """Execute production tasks locally with only an owned fake transport."""
    with tempfile.TemporaryDirectory(prefix='native-container-contract-') as temporary:
        directory = Path(temporary)
        fixture = directory / 'responses.json'
        fixture.write_text(json.dumps(responses))
        calls = directory / 'calls.jsonl'
        docker = directory / 'docker'
        docker.write_text('#!' + sys.executable + '\n'
                          + 'CALLS = ' + repr(str(calls)) + '\n'
                          + 'RESPONSES = ' + repr(str(fixture)) + '\n' + '''
import base64, json, os, sys, time
from pathlib import Path
calls = Path(CALLS)
index = len(calls.read_text().splitlines()) if calls.exists() else 0
with calls.open('a') as log:
    log.write(json.dumps([Path(sys.argv[0]).name] + sys.argv[1:]) + '\\n')
responses = json.loads(Path(RESPONSES).read_text())
if index >= len(responses):
    raise SystemExit('unexpected Docker call')
item = responses[index]
if 'health' in item:
    health = list(item['health'])
    health[1] = os.getppid()
    item['stdout'] = json.dumps(health)
if item.get('sleep'):
    time.sleep(item['sleep'])
for stream, value in item.get('streams', []):
    os.write(1 if stream == 'stdout' else 2, value.encode('utf-8'))
value = item.get('stdout', '')
os.write(1, base64.b64decode(value) if item.get('base64') else value.encode('utf-8'))
os.write(2, item.get('stderr', '').encode('utf-8'))
raise SystemExit(item.get('rc', 0))
''')
        docker.chmod(0o700)
        nsenter = directory / 'nsenter'
        nsenter.write_bytes(docker.read_bytes())
        nsenter.chmod(0o700)
        play = directory / 'play.yml'
        play.write_text(yaml.safe_dump([{
            'hosts': 'all', 'gather_facts': False,
            'vars': {'ansible_python_interpreter': sys.executable, **variables},
            'tasks': tasks,
        }], sort_keys=False))
        result = subprocess.run(
            ['ansible-playbook', '-i', '127.0.0.1,', '-c', 'local', str(play)],
            env={**os.environ, 'PATH': str(directory) + ':' + os.environ['PATH'],
                 'HOME': str(directory),
                 'NATIVE_CONTRACT_CALLS': str(calls),
                 'NATIVE_CONTRACT_RESPONSES': str(fixture),
                 'ANSIBLE_LOCAL_TEMP': str(directory / 'controller'),
                 'ANSIBLE_REMOTE_TEMP': str(directory / 'remote')},
            capture_output=True, text=True, timeout=timeout,
        )
        observed = [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []
        return result, observed


class ContainerDeployNativeTests(unittest.TestCase):
    def setUp(self):
        self.play = yaml.safe_load((CATALOG / 'playbooks/container_deploy.yml').read_text())
        self.tasks = self.play[0]['pre_tasks'] + self.play[0]['tasks']
        self.context = {
            'container_name': 'selected', 'app_org_id': '00000000-0000-0000-0000-000000000001',
            'app_project_id': '', 'app_slug': 'application', 'deploy_host_ports': [18175, 15175],
            'host_port_preflight_enabled': True, 'replace_conflicts': True,
            'managed_image_resources': False,
        }

    def task(self, name):
        task = named(self.tasks, name)
        self.assertIsNotNone(task, name)
        return task

    def test_conflicts_preserve_port_matching_and_only_exclude_the_owned_target(self):
        labels = {'com.opsctl.managed': 'true', 'com.opsctl.org_id': self.context['app_org_id'],
                  'com.opsctl.app': 'application'}
        for owned, project, replacement in ((True, '', False), (False, '', False),
                                             (True, 'other-project', False), (True, '', True)):
            with self.subTest(owned=owned, project=project, replacement=replacement):
                context = {**self.context, 'app_project_id': project}
                if replacement:
                    context['source_replacement'] = {'intent': 'selected'}
                metadata = {'Config': {'Labels': {**labels, 'com.opsctl.managed': 'true' if owned else 'false'}}}
                result, calls = run_tasks([
                    self.task('Detect host port conflicts'), self.task('Parse port conflict results'),
                    {'ansible.builtin.assert': {'that': [
                        'port_conflict_entries == expected_conflicts']}}
                ], {**context, 'expected_conflicts':
                    ([{'name': 'selected', 'ports': [18175]}] if not owned or project or replacement else [])
                    + [{'name': 'foreign', 'ports': [15175, 18175]}]}, [
                    response('selected\t127.0.0.1:18175->80/tcp\nforeign\t[::]:15175->80/tcp, 0.0.0.0:18175->81/tcp\n'),
                    response([metadata]),
                ])
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(len(calls), 1 if replacement else 2)
                self.assertFalse(any(call[1] in ('rm', 'create', 'start') for call in calls))

    def test_conflict_recheck_error_is_retained_only_for_the_source_restore_path(self):
        for verified in (False, True):
            with self.subTest(verified=verified):
                result, calls = run_tasks([
                    self.task('Re-check host port conflicts after removal'),
                    self.task('Parse post-removal conflicts'),
                    {'ansible.builtin.assert': {'that': [
                        'source_replacement_recheck_failed', 'source_replacement_recheck_complete']}}
                ], {**self.context, 'port_conflict_entries': [{'name': 'selected'}],
                    'source_replacement_verified': verified}, [response(code=1)])
                self.assertEqual(result.returncode == 0, verified, result.stdout + result.stderr)
                self.assertEqual(len(calls), 1)

    def test_removable_and_legacy_candidates_preserve_label_and_project_confinement(self):
        own = {'Name': '/owned', 'Config': {'Labels': {
            'com.opsctl.managed': 'true', 'com.opsctl.org_id': self.context['app_org_id'],
            'com.opsctl.app': 'application', 'com.opsctl.project_id': 'chosen'}}}
        foreign = copy.deepcopy(own)
        foreign['Name'] = '/foreign'
        foreign['Config']['Labels']['com.opsctl.org_id'] = 'foreign'
        for task, output, expected in (
            ('Determine removable conflict containers', 'removable_conflicts', ['owned']),
            ('Discover legacy OpsCtl-managed containers for deployment identity', 'legacy_opsctl_containers_result', ['owned']),
        ):
            with self.subTest(task=task):
                responses = [response([own, foreign])]
                if task.startswith('Discover'):
                    responses.insert(0, response('owned\nforeign\n'))
                result, calls = run_tasks([
                    self.task(task), {'ansible.builtin.assert': {'that':
                        [f'({output}.stdout | from_json) == expected']}}
                ], {**self.context, 'app_project_id': 'chosen', 'expected': expected,
                    'port_conflict_entries': [{'name': 'owned'}, {'name': 'foreign'}]}, responses)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(any(call[1] == 'rm' for call in calls))

    def test_case_distinct_managed_names_are_retained_in_python_sort_order(self):
        labels = {'com.opsctl.managed': 'true', 'com.opsctl.org_id': self.context['app_org_id'],
                  'com.opsctl.app': 'application'}
        containers = [{'Name': '/' + name, 'Config': {'Labels': labels}}
                      for name in ('owned', 'Owned', 'owned')]
        for task, output in (
            ('Determine removable conflict containers', 'removable_conflicts'),
            ('Discover legacy OpsCtl-managed containers for deployment identity',
             'legacy_opsctl_containers_result'),
        ):
            with self.subTest(task=task):
                observed = containers if task.startswith('Discover') else containers[:2]
                responses = [response(observed)]
                if task.startswith('Discover'):
                    responses.insert(0, response('owned\nOwned\nowned\n'))
                result, calls = run_tasks([
                    self.task(task), {'ansible.builtin.assert': {'that': [
                        f'({output}.stdout | from_json) == expected_names']}}
                ], {**self.context, 'expected_names': ['Owned', 'owned'],
                    'port_conflict_entries': [{'name': 'owned'}, {'name': 'Owned'}]}, responses)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(any(call[1] in ('rm', 'create', 'start') for call in calls))

    def replacement(self):
        return {
            'intent': 'replace_exact_source_container', 'container_name': 'selected',
            'app_slug': 'application', 'org_id': self.context['app_org_id'], 'project_id': None,
            'deployment_id': '00000000-0000-0000-0000-000000000002', 'image': 'image:retained',
            'current_exposure_modes': ['loopback', 'loopback_wireguard'],
            'exposure_mode': 'loopback_wireguard', 'wireguard_ip': '10.99.0.2',
            'route_port': 18175, 'container_port': 80, 'replace_conflicts': True,
        }

    def test_exact_replacement_refuses_identity_and_bindings_before_mutation(self):
        expected = self.replacement()
        runtime = {'Config': {'Image': expected['image'], 'Labels': {
            'com.opsctl.managed': 'true', 'com.opsctl.org_id': expected['org_id'],
            'com.opsctl.app': expected['app_slug'], 'com.opsctl.deployment_id': expected['deployment_id']}},
            'HostConfig': {}, 'NetworkSettings': {'Ports': {'80/tcp': [
                {'HostIp': '127.0.0.1', 'HostPort': '18175'}]}}}
        for change in ('valid', 'foreign_deployment', 'foreign_org', 'image', 'wildcard', 'extra_port', 'port_text'):
            with self.subTest(change=change):
                actual = copy.deepcopy(runtime)
                if change.startswith('foreign_'):
                    actual['Config']['Labels']['com.opsctl.' + ('deployment_id' if change == 'foreign_deployment' else 'org_id')] = 'foreign'
                elif change == 'image':
                    actual['Config']['Image'] = 'foreign-image'
                elif change == 'wildcard':
                    actual['NetworkSettings']['Ports']['80/tcp'][0]['HostIp'] = '0.0.0.0'
                elif change == 'extra_port':
                    actual['NetworkSettings']['Ports']['81/tcp'] = []
                elif change == 'port_text':
                    actual['NetworkSettings']['Ports']['80/tcp'][0]['HostPort'] = '18175.0'
                result, calls = run_tasks([self.task('Validate exact source replacement container')], {
                    **self.context, 'source_replacement': expected,
                    'port_conflict_entries': [{'name': 'selected', 'ports': [18175]}]}, [response([actual])])
                self.assertEqual(result.returncode == 0, change == 'valid', result.stdout + result.stderr)
                self.assertEqual(calls, [['docker', 'inspect', 'selected']])

    def test_all_six_source_rescues_share_the_native_restore_and_health_boundary(self):
        consumers = []
        def collect(tasks):
            for task in tasks:
                include = task.get('ansible.builtin.include_tasks', '')
                if isinstance(include, str) and include.endswith('container_source_runtime_restore.yml'):
                    consumers.append(task)
                for section in ('tasks', 'pre_tasks', 'block', 'rescue', 'always'):
                    collect(task.get(section, []))
        collect(self.play)
        collect(yaml.safe_load((CATALOG / 'tasks/container_image_prepare.yml').read_text()))
        self.assertEqual(len(consumers), 6)
        self.assertTrue(all(task['no_log'] for task in consumers))
        restore = yaml.safe_load((CATALOG / 'tasks/container_source_runtime_restore.yml').read_text())
        health = named(restore, 'Probe the restored source container HTTP endpoint')
        self.assertEqual(health['timeout'], 35)
        self.assertEqual(health['ansible.builtin.script']['executable'], 'python3')
        self.assertIn('../scripts/container_http_health.py', health['ansible.builtin.script']['cmd'])
        for name in ('Require exact restored source configuration', 'Require exact restored published ports',
                     'Require exact restored bind mounts', 'Require the restored source to be running'):
            self.assertIsNotNone(named(restore, name))

    def test_source_restore_preserves_argv_configuration_and_confined_health(self):
        tasks = yaml.safe_load((CATALOG / 'tasks/container_source_runtime_restore.yml').read_text())
        tasks = copy.deepcopy(tasks)
        health = named(tasks, 'Probe the restored source container HTTP endpoint')
        health['ansible.builtin.script']['cmd'] = health['ansible.builtin.script']['cmd'].replace(
            '../scripts/container_http_health.py', str(CATALOG / 'scripts/container_http_health.py'))
        expected = self.replacement()
        config = {'Image': 'image:retained', 'Cmd': ['serve', '$HOME/${HOME}'],
                  'Entrypoint': ['/entrypoint'], 'Env': ['KEY=$HOME/${HOME}'],
                  'WorkingDir': '/work', 'User': '1000', 'Labels': {
                      'lower': '$HOME', 'Lower': '${HOME}',
                      'com.opsctl.managed': 'true', 'com.opsctl.org_id': expected['org_id'],
                      'com.opsctl.deployment_id': expected['deployment_id']}}
        host = {'RestartPolicy': {'Name': 'unless-stopped'}, 'NetworkMode': 'bridge',
                'Binds': ['/owned/$HOME/${HOME}:/data:ro'],
                'PortBindings': {'80/tcp': [{'HostIp': '::1', 'HostPort': '18175'}]}}
        final = {'Config': config, 'HostConfig': host, 'State': {'Running': True}}
        identity = ['a' * 64, None, True, 'saved-start', 'true', expected['org_id'], expected['deployment_id'], '']
        for mode in ('healthy', 'config_drift', 'bindings_drift', 'mount_drift', 'not_running', 'health_refused'):
            with self.subTest(mode=mode):
                actual = copy.deepcopy(final)
                if mode == 'config_drift':
                    actual['Config']['Env'] = []
                elif mode == 'bindings_drift':
                    actual['HostConfig']['PortBindings'] = {}
                elif mode == 'mount_drift':
                    actual['HostConfig']['Binds'] = []
                elif mode == 'not_running':
                    actual['State']['Running'] = False
                responses = [response(), response(), response(), response([actual])]
                if mode == 'healthy':
                    responses += [response(health=identity), response(health=identity), response(), response(health=identity)]
                elif mode == 'health_refused':
                    responses += [response(code=1)]
                result, calls = run_tasks(tasks, {
                    'source_replacement': expected,
                    'source_replacement_original': {'name': 'selected', 'config': config, 'host_config': host},
                    'app_health_container_path': '/health',
                }, responses)
                self.assertEqual(result.returncode == 0, mode == 'healthy', result.stdout + result.stderr)
                self.assertEqual(calls[:4], [
                    ['docker', 'rm', '-f', 'selected'],
                    ['docker', 'create', '--name', 'selected', '--restart', 'unless-stopped',
                     '--network', 'bridge', '--workdir', '/work', '--user', '1000',
                     '--entrypoint', '/entrypoint', '--env', 'KEY=$HOME/${HOME}',
                     '--label', 'Lower=${HOME}',
                     '--label', 'com.opsctl.deployment_id=' + expected['deployment_id'],
                     '--label', 'com.opsctl.managed=true', '--label', 'com.opsctl.org_id=' + expected['org_id'],
                     '--label', 'lower=$HOME',
                     '--volume', '/owned/$HOME/${HOME}:/data:ro', '--publish', '[::1]:18175:80/tcp',
                     'image:retained', 'serve', '$HOME/${HOME}'],
                    ['docker', 'start', 'selected'], ['docker', 'inspect', 'selected'],
                ])
                self.assertNotIn('KEY=$HOME/${HOME}', result.stdout + result.stderr)
                if mode == 'healthy':
                    self.assertEqual(calls[-2][0], 'nsenter')
                    self.assertTrue(calls[-2][1].startswith('--net=/proc/self/fd/'))
                    self.assertEqual(calls[-2][-2:], ['80', '/health'])
                elif mode != 'health_refused':
                    self.assertEqual(len(calls), 4)

    def test_diagnostics_preserve_merged_order_deduplication_and_utf8_byte_cap(self):
        tasks = yaml.safe_load((CATALOG / 'tasks/container_failure_diagnostics.yml').read_text())
        logs_task = named(tasks, 'Read merged log bytes without changing stream order')
        self.assertEqual(logs_task['args']['executable'], '/bin/bash')
        tasks = copy.deepcopy(tasks)
        named(tasks, 'Read merged log bytes without changing stream order')['args']['executable'] = '/bin/sh'
        pipeline = subprocess.run(['/bin/sh', '-c', 'set -o pipefail; (exit 7) | cat'],
                                  capture_output=True, text=True, timeout=10)
        self.assertEqual(pipeline.returncode, 7, pipeline.stdout + pipeline.stderr)
        payload = ('é' * 9000 + '\n').encode('utf-8')
        log_prefix = 'Container log tail:\n'
        for logs, expected in (
            (response(streams=[('stdout', 'first\n'), ('stderr', 'second\n'), ('stdout', 'first\n')]), 'first\nsecond'),
            (response(b'one\n\xff\none\n'), 'one\n\ufffd'),
            (response(payload), ('é' * 8184) + '\n... [truncated]'),
            (response('a' * 16366 + 'rn' + 'overflow' * 3), 'a' * 16366 + 'rn\n... [truncated]'),
            (response(code=1), None),
        ):
            with self.subTest(expected=expected[:30] if expected else None):
                marker = 'Container logs unavailable.' if expected is None else log_prefix + expected
                result, calls = run_tasks(tasks + [{'ansible.builtin.assert': {'that': [
                    'container_failure_logs == expected_logs',
                    "container_failure_logs.removeprefix(expected_prefix).encode('utf-8') | length <= 16384"]}}],
                    {'container_name': 'selected', 'expected_logs': marker, 'expected_prefix': log_prefix},
                    [response('status=exited\n'), logs])
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(calls[-1], ['docker', 'logs', '--tail', '100', 'selected'])

    def test_diagnostics_timeout_is_best_effort_and_cannot_replace_the_failure(self):
        tasks = yaml.safe_load((CATALOG / 'tasks/container_failure_diagnostics.yml').read_text())
        logs_task = named(tasks, 'Read merged log bytes without changing stream order')
        self.assertEqual(logs_task['args']['executable'], '/bin/bash')
        tasks = copy.deepcopy(tasks)
        named(tasks, 'Read merged log bytes without changing stream order')['args']['executable'] = '/bin/sh'
        started = time.monotonic()
        result, calls = run_tasks(tasks + [{'ansible.builtin.fail': {'msg': 'original_failure_marker'}}],
            {'container_name': 'selected'}, [response(sleep=12), response(code=1)], timeout=40)
        self.assertLess(time.monotonic() - started, 35)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('original_failure_marker', result.stdout)
        self.assertEqual(len(calls), 2)


if __name__ == '__main__':
    unittest.main()
