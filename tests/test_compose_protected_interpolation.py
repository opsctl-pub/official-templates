#!/usr/local/bin/python
"""Production Compose task boundaries with an explicitly substituted daemon CLI."""

from contextlib import contextmanager
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

import yaml


def substituted_docker():
    """Record safe CLI facts without contacting a daemon or claiming observation."""
    control = json.loads(Path('/proof/transport-control.json').read_text())
    args = sys.argv[1:]
    files = []
    for index, argument in enumerate(args[:-1]):
        if argument != '--env-file':
            continue
        path = Path(args[index + 1])
        if not path.is_absolute():
            path = Path.cwd() / path
        files.append({
            'path': str(path), 'bytes': path.stat().st_size,
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
            'mode': stat.S_IMODE(path.stat().st_mode),
        })
    with Path(control['trace']).open('a') as stream:
        stream.write(json.dumps({
            'argv': args, 'environment_keys': sorted(os.environ),
            'path': os.environ.get('PATH'), 'docker_config': os.environ.get('DOCKER_CONFIG'),
            'env_files': files,
        }) + '\n')
    if args[:2] != ['--host', 'unix:///var/run/docker.sock']:
        return 91
    if 'compose' not in args:
        print(json.dumps({'Client': {'Version': '27.0.0'},
                          'Server': {'Version': '27.0.0', 'ApiVersion': '1.46'}}))
    elif 'version' in args:
        print(json.dumps({'version': '2.33.0'}))
    elif 'config' in args:
        print(json.dumps({'services': {'app': {'image': 'busybox:latest', 'restart': 'always'}}}))
    elif 'up' in args:
        return 37 if control['fail'] else 0
    elif 'ps' in args or 'images' in args:
        print('[]')
    else:
        return 92
    return 0


if __name__ == '__main__' and sys.argv[1:2] == ['--host']:
    sys.exit(substituted_docker())


ROOT = Path(__file__).resolve().parents[1]
PLAYBOOK = ROOT / 'catalog/ansible/playbooks/compose_deploy.yml'
HELPER = ROOT / 'catalog/ansible/scripts/compose_controlled_environment.sh'
PROTECTED = b'EMPTY=""\nLITERAL="\\$HOME\\nprivate-protected-marker"\n'
CONTROL = Path('/proof/transport-control.json')


@contextmanager
def frozen_inputs(case):
    """Own all synthetic sources, target effects and transport-control metadata."""
    with tempfile.TemporaryDirectory(prefix='compose-protected-') as temporary:
        root = Path(temporary)
        staged = root / 'staged'
        staged.mkdir()
        payloads = {'source-00': b'services:\n  app:\n    image: busybox:latest\n    restart: always\n',
                    'source-01': b'BASE=captured\n', 'source-02': b'BASE=first\n',
                    'source-03': b'BASE=second\n'}
        for name, payload in payloads.items():
            (staged / name).write_bytes(payload)
        if case in ('default', 'ordered', 'failure'):
            projection = staged / '..frozen'
            projection.mkdir()
            (projection / 'protected').write_bytes(PROTECTED)
            (staged / 'compose-interpolation.env').symlink_to('..frozen/protected')
        elif case == 'escaped':
            (root / 'outside.env').write_bytes(PROTECTED)
            (staged / 'compose-interpolation.env').symlink_to('../outside.env')
        elif case == 'oversized':
            (staged / 'compose-interpolation.env').write_bytes(b'x' * 262145)
        for path in staged.rglob('*'):
            if not path.is_symlink():
                path.chmod(0o500 if path.is_dir() else 0o400)
        staged.chmod(0o500)
        sentinel = root / 'unrelated-sentinel'
        sentinel.write_bytes(b'unrelated-sentinel')
        sentinel.chmod(0o640)
        try:
            yield root, staged, payloads, sentinel
        finally:
            for path in staged.rglob('*'):
                if path.is_dir() and not path.is_symlink():
                    path.chmod(0o700)
            staged.chmod(0o700)
            CONTROL.unlink(missing_ok=True)


class ComposeProtectedInterpolationTests(unittest.TestCase):
    def invoke(self, root, staged, case):
        """Run unchanged selected task bodies, excluding real native observation."""
        play = yaml.safe_load(PLAYBOOK.read_text())[0]
        procedure = play['tasks'][2]
        tasks = procedure['block']
        names = [task['name'] for task in tasks]
        selected = tasks[:6] + tasks[
            names.index('Select file-delivery failure'):
            names.index('Reobserve current resources and membership immediately before native apply')
        ]
        apply = next(task for task in tasks if 'community.docker.docker_compose_v2' in task)
        options = apply['community.docker.docker_compose_v2']
        self.assertNotIn('cli_context', options)
        self.assertEqual(options['docker_host'], 'unix:///var/run/docker.sock')
        for option, expected in {'tls': False, 'validate_certs': False, 'tls_hostname': None,
                                 'ca_path': None, 'client_cert': None, 'client_key': None,
                                 'api_version': 'auto'}.items():
            self.assertIn(option, options)
            self.assertEqual(options[option], expected)
        selected += [{'name': 'Set diagnostic original apply reason without observation',
                      'ansible.builtin.set_fact': {'compose_reason': 'compose_apply_failed'}}, apply]
        workspace = root / 'workspace'
        refused = case in ('escaped', 'missing', 'oversized')
        if not refused:
            workspace.mkdir()
            (workspace / '.env').write_bytes(b'BASE=retained-unsupplied\n')
        supplied = [{'path': 'compose.yaml', 'source': 'source-00', 'mode': '0644'}]
        if case != 'empty':
            supplied.append({'path': '.env', 'source': 'source-01', 'mode': '0600'})
        if case == 'ordered':
            supplied += [{'path': 'first.env', 'source': 'source-02', 'mode': '0600'},
                         {'path': 'second.env', 'source': 'source-03', 'mode': '0600'}]
        parameters = {
            'compose_project_name': 'protected-regression', 'compose_workspace': str(workspace),
            'compose_source_directory': str(staged), 'compose_files': ['compose.yaml'],
            'compose_env_files': ['first.env', 'second.env'] if case == 'ordered' else [],
            'compose_supplied_files': supplied, 'compose_profiles': [],
            'compose_services': [{'name': 'app', 'replicas': 1, 'condition': 'running',
                                  'allow_completion': False}],
        }
        if case != 'empty':
            parameters['compose_interpolation_source_file'] = str(staged / 'compose-interpolation.env')
        trace = root / 'trace.jsonl'
        CONTROL.write_text(json.dumps({'trace': str(trace), 'fail': case == 'failure'}))
        CONTROL.chmod(0o600)
        outcome = root / 'facts.json'
        summary = {
            'reason': '{{ compose_reason }}', 'failure_reason': '{{ compose_failure_reason | default(none) }}',
            'failed_task': '{{ regression_failed_task | default(none) }}',
            'failed_rc': '{{ regression_failed_rc | default(none) }}',
            'auth_directory': '{{ compose_auth_directory.path | default(none) }}',
            'cleanup_observed': '{{ compose_cleanup_after.stat is defined }}',
            'cleanup_absent': '{{ not (compose_cleanup_after.stat.exists | default(false)) }}',
            'delivered': '{{ compose_files_written }}',
            'module_failed': '{{ compose_native_apply.failed | default(false) }}',
        }
        playbooks = root / 'playbooks'
        playbooks.mkdir()
        (root / 'scripts').symlink_to(HELPER.parent)
        generated = [{
            'name': 'Substituted daemon transport, no complete observation or public result',
            'hosts': 'all', 'gather_facts': False, 'become': False,
            'vars': {**play['vars'], **parameters},
            'tasks': [play['tasks'][0], {
                'name': procedure['name'], 'block': copy.deepcopy(selected), 'no_log': True,
                'rescue': [procedure['rescue'][0], {
                    'name': 'Retain diagnostic failed task attribution',
                    'ansible.builtin.set_fact': {
                        'regression_failed_task': '{{ ansible_failed_task.name }}',
                        'regression_failed_rc': '{{ ansible_failed_result.rc | default(none) }}',
                    },
                }], 'always': copy.deepcopy(procedure['always']),
            }, {'name': 'Prepare safe diagnostic subset facts', 'ansible.builtin.set_fact': {
                'regression_summary': summary}}, {
                'name': 'Save diagnostic facts, not public deployment success',
                'ansible.builtin.copy': {'dest': str(outcome), 'mode': '0600',
                                         'content': '{{ regression_summary | to_json }}'},
            }],
        }]
        invocation = playbooks / 'subset.yml'
        invocation.write_text(yaml.safe_dump(generated, sort_keys=False))
        environment = {
            **os.environ, 'TMPDIR': str(root), 'ANSIBLE_LOCAL_TEMP': str(root / 'ansible-local'),
            'ANSIBLE_REMOTE_TEMP': str(root / 'ansible-remote'),
            'DOCKER_HOST': 'tcp://forbidden.invalid:2376', 'DOCKER_CONTEXT': 'forbidden',
            'DOCKER_TLS': '1', 'DOCKER_TLS_VERIFY': '1', 'DOCKER_TLS_HOSTNAME': 'forbidden',
            'DOCKER_API_VERSION': '0.01', 'COMPOSE_FILE': '/forbidden',
            'COMPOSE_PROJECT_NAME': 'forbidden', 'APP_PRIVATE_VALUE': 'private-ambient-marker',
        }
        result = subprocess.run(
            ['ansible-playbook', '-i', '127.0.0.1,', '-c', 'local', str(invocation)],
            env=environment, capture_output=True, text=True, timeout=150,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn('private-protected-marker', result.stdout + result.stderr)
        self.assertNotIn('private-ambient-marker', result.stdout + result.stderr)
        facts = json.loads(outcome.read_text())
        records = [json.loads(line) for line in trace.read_text().splitlines()] if trace.exists() else []
        return workspace, supplied, facts, records

    def assert_sentinel(self, sentinel):
        self.assertEqual(sentinel.read_bytes(), b'unrelated-sentinel')
        self.assertEqual(stat.S_IMODE(sentinel.stat().st_mode), 0o640)

    def assert_delivery_and_cleanup(self, workspace, staged, supplied, facts):
        self.assertEqual(facts['delivered'], [file['path'] for file in supplied])
        for file in supplied:
            delivered = workspace / file['path']
            self.assertEqual(delivered.read_bytes(), (staged / file['source']).read_bytes())
            self.assertEqual(stat.S_IMODE(delivered.stat().st_mode), int(file['mode'], 8))
        self.assertIsNotNone(facts['auth_directory'])
        self.assertTrue(facts['cleanup_observed'])
        self.assertTrue(facts['cleanup_absent'])
        self.assertFalse(Path(facts['auth_directory']).exists())

    def assert_controlled_calls(self, records):
        config = next(record for record in records if 'config' in record['argv'])
        apply = next(record for record in records if 'up' in record['argv'])
        self.assertEqual(config['env_files'], apply['env_files'])
        for record in records:
            self.assertEqual(record['argv'][:2], ['--host', 'unix:///var/run/docker.sock'])
            self.assertEqual(set(record['environment_keys']), {'PATH', 'DOCKER_CONFIG'})
            self.assertEqual(record['path'], '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin')
            for flag in ('--context', '--tls', '--tlsverify', '--force-recreate', '--renew-anon-volumes'):
                self.assertNotIn(flag, record['argv'])
        self.assertIn('--no-build', apply['argv'])
        self.assertIn('--remove-orphans', apply['argv'])
        return apply['env_files']

    def test_default_ordered_and_empty_lists_preserve_captured_data_and_cleanup(self):
        for case in ('default', 'ordered', 'empty'):
            with self.subTest(case=case), frozen_inputs(case) as (root, staged, payloads, sentinel):
                before = {name: hashlib.sha256((staged / name).read_bytes()).hexdigest() for name in payloads}
                workspace, supplied, facts, records = self.invoke(root, staged, case)
                self.assertIsNone(facts['failed_task'])
                self.assertFalse(facts['module_failed'])
                self.assert_delivery_and_cleanup(workspace, staged, supplied, facts)
                files = self.assert_controlled_calls(records)
                if case == 'empty':
                    self.assertEqual(len(files), 1)
                    self.assertEqual(files[0]['bytes'], 0)
                    self.assertEqual(files[0]['mode'], 0o600)
                    self.assertEqual(Path(files[0]['path']).name, 'empty.env')
                    self.assertEqual((workspace / '.env').read_bytes(), b'BASE=retained-unsupplied\n')
                else:
                    self.assertEqual([Path(file['path']).name for file in files[:-1]],
                                     ['first.env', 'second.env'] if case == 'ordered' else ['.env'])
                    self.assertEqual(files[-1]['sha256'], hashlib.sha256(PROTECTED).hexdigest())
                    self.assertEqual(files[-1]['mode'], 0o600)
                    self.assertEqual(Path(files[-1]['path']).name, 'compose-interpolation.env')
                self.assertEqual(before, {name: hashlib.sha256((staged / name).read_bytes()).hexdigest() for name in payloads})
                self.assert_sentinel(sentinel)

    def test_apply_failure_preserves_original_reason_and_removes_private_material(self):
        with frozen_inputs('failure') as (root, staged, payloads, sentinel):
            workspace, supplied, facts, records = self.invoke(root, staged, 'failure')
            self.assertTrue(facts['module_failed'])
            self.assertEqual(facts['failed_rc'], 37)
            self.assertEqual(facts['reason'], 'compose_apply_failed')
            self.assertEqual(facts['failure_reason'], 'compose_apply_failed')
            self.assert_delivery_and_cleanup(workspace, staged, supplied, facts)
            self.assert_controlled_calls(records)
            self.assert_sentinel(sentinel)

    def test_escaped_missing_and_oversized_sources_refuse_before_delivery(self):
        for case in ('escaped', 'missing', 'oversized'):
            with self.subTest(case=case), frozen_inputs(case) as (root, staged, payloads, sentinel):
                workspace, supplied, facts, records = self.invoke(root, staged, case)
                self.assertFalse(workspace.exists())
                self.assertEqual(records, [])
                self.assertEqual(facts['delivered'], [])
                self.assertIsNone(facts['auth_directory'])
                self.assertFalse(facts['cleanup_observed'])
                self.assertEqual(facts['failure_reason'], 'compose_prerequisite_unavailable')
                self.assertIsNotNone(facts['failed_task'])
                self.assert_sentinel(sentinel)


if __name__ == '__main__':
    unittest.main()
