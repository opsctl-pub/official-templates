"""Existing image preparation tasks with observation-only transport fixtures."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import jinja2
import yaml


ROOT = Path(__file__).resolve().parents[1]
PLAYBOOK = ROOT / 'catalog/ansible/playbooks/container_deploy.yml'


class PlatformPreparationTests(unittest.TestCase):
    def test_actual_preparation_cached_pulled_mismatch_and_unknown_before_mutations(self):
        tasks = yaml.safe_load(PLAYBOOK.read_text())[0]['tasks']
        inspect = next(task for task in tasks if task['name'].startswith('Inspect local image'))
        prepare = next(task for task in tasks if task['name'] == 'Prepare compatible container image')
        for mode, expected, pull in (
            ('cached', None, False), ('pulled', None, True),
            ('cached_wrong', 'image_platform_mismatch', False),
            ('pulled_wrong', 'image_platform_mismatch', True),
            ('unknown', 'image_platform_unavailable', False),
            ('higher', 'image_platform_unavailable', False),
            ('index_wrong', 'image_platform_mismatch', True),
        ):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix='platform-tasks-') as temporary:
                directory = Path(temporary)
                calls = directory / 'calls.jsonl'
                marker = directory / 'workload-changed'
                docker = directory / 'docker'
                docker.write_text('''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
mode = os.environ['OBSERVATION_MODE']
with open(os.environ['OBSERVATION_CALLS'], 'a') as log:
    log.write(json.dumps(sys.argv[1:]) + '\\n')
if sys.argv[1] == 'info':
    print(json.dumps({'os': 'linux', 'architecture': 'unknown' if mode == 'unknown' else 'x86_64'}))
elif sys.argv[1:3] == ['image', 'inspect']:
    if mode in {'pulled', 'pulled_wrong', 'index_wrong'} and not Path(os.environ['OBSERVATION_PULL']).exists():
        raise SystemExit(1)
    print(json.dumps({'os': 'linux', 'architecture': 'arm64' if 'wrong' in mode else 'amd64',
                      'variant': 'v2' if mode == 'higher' else 'v8' if 'wrong' in mode else 'v1'}))
elif sys.argv[1] == 'pull':
    if mode == 'index_wrong':
        print('no matching manifest for linux/amd64 in the manifest list entries', file=sys.stderr)
        raise SystemExit(1)
    Path(os.environ['OBSERVATION_PULL']).touch()
else:
    raise SystemExit('unexpected Docker command')
''')
                docker.chmod(0o700)
                play = [{'hosts': 'all', 'gather_facts': False, 'vars': {
                    'app_image': 'ghcr.io/proof/image@sha256:' + 'a' * 64,
                    'source_replacement_transaction_active': False,
                    'source_replacement_removed': False},
                    'tasks': [inspect, prepare, {'name': 'Fixture workload mutation boundary',
                        'ansible.builtin.command': {'argv': ['touch', str(marker)]}}]}]
                path = directory / 'play.yml'
                path.write_text(yaml.safe_dump(play, sort_keys=False))
                result = subprocess.run(['ansible-playbook', '-i', '127.0.0.1,', '-c', 'local', str(path)],
                    env={**os.environ, 'PATH': str(directory) + ':' + os.environ['PATH'],
                         'OBSERVATION_MODE': mode, 'OBSERVATION_CALLS': str(calls),
                         'OBSERVATION_PULL': str(directory / 'pulled')},
                    capture_output=True, text=True, timeout=60)
                commands = [json.loads(line) for line in calls.read_text().splitlines()]
                self.assertEqual(any(command[0] == 'pull' for command in commands), pull)
                if expected:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(expected, result.stdout)
                    self.assertFalse(marker.exists())
                    self.assertNotIn('TEMPLATE_OUTPUT_JSON=', result.stdout)
                else:
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertTrue(marker.exists())

    def test_shared_preparation_precedes_source_conflict_legacy_and_compose(self):
        text = PLAYBOOK.read_text()
        preparation = text.index('- name: Prepare compatible container image')
        for name in ('Mark source replacement transaction active',
                     'Converge the shared reviewed Compose deployment'):
            self.assertLess(preparation, text.index('- name: ' + name))
        self.assertLess(preparation, text.index('docker rm -f'))
        self.assertIn('pull_policy: never', (ROOT / 'catalog/ansible/templates/container_compose.yml.j2').read_text())
        self.assertNotIn('image_platforms', text)

    def test_actual_compose_template_empty_absent_and_literal_dollar_environment(self):
        source = (ROOT / 'catalog/ansible/templates/container_compose.yml.j2').read_text()
        environment = jinja2.Environment(undefined=jinja2.StrictUndefined)
        environment.filters['to_json'] = json.dumps
        template = environment.from_string(source)
        runtime = {'deployment_id': 'deployment', 'organization_id': 'org', 'server_id': 'server',
            'operation_id': 'operation', 'revision_id': 'revision', 'app_slug': 'app',
            'container_name': 'fixture', 'image': 'image@sha256:' + 'a' * 64,
            'mounts': [], 'networks': [], 'labels': {}, 'command': ['echo', '$literal']}
        for env in (None, {}, {'VALUE': '$literal:${MISSING}:$$'}):
            with self.subTest(env=env):
                request = dict(runtime)
                if env is not None:
                    request['env'] = env
                rendered = yaml.safe_load(template.render(app_local_runtime=request))
                actual = rendered['services']['app']
                self.assertEqual(actual['environment'], {} if not env else {'VALUE': '$$literal:$${MISSING}:$$$$'})
                self.assertEqual(actual['command'], ['echo', '$$literal'])


if __name__ == '__main__':
    unittest.main()
