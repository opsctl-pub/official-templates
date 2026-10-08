"""Existing image preparation tasks with observation-only transport fixtures."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import jinja2
import yaml

from test_container_deploy_native import named, run_tasks


ROOT = Path(__file__).resolve().parents[1]
PLAYBOOK = ROOT / 'catalog/ansible/playbooks/container_deploy.yml'
PREPARATION = ROOT / 'catalog/ansible/tasks/container_image_prepare.yml'


class PlatformPreparationTests(unittest.TestCase):
    def test_native_platform_parser_preserves_strict_raw_input_refusals(self):
        tasks = yaml.safe_load(PREPARATION.read_text())
        compare = named(tasks, 'Compare prepared image with actual Docker platform')
        require = named(tasks, 'Require compatible prepared image')
        daemon = '{"os":"linux","architecture":"x86_64"}'
        image = '{"os":"linux","architecture":"amd64","variant":"v1"}'
        invalid = (
            '{"os":"linux","os":"linux","architecture":"amd64","variant":"v1"}',
            '{"os":"linux","\\u006fs":"linux","architecture":"amd64","variant":"v1"}',
            '{"os":"linux","architecture":"amd64","variant":"v1"',
            '[]', 'null', 'true',
            '{"os":"linux","architecture":true,"variant":"v1"}',
            '{"os":"linux","architecture":"amd64","variant":"v2"}',
            '{"os":"linux","architecture":"arm64","variant":"v7"}',
            '{"os":"linux","architecture":"arm","variant":""}',
            '{"os":"linux","architecture":"amd64","variant":null}',
            '{"os":"linux","architecture":"amd64","variant":"v1","extra":"value"}',
            '{"os":"linux","architecture":"' + 'é' * 2050 + '","variant":"v1"}',
            '{"os":"linux","architecture":"amd64","variant":"' + 'a' * 33 + '"}',
        )
        for raw in invalid:
            with self.subTest(raw=raw[:80]):
                result, calls = run_tasks([compare, require], {
                    'daemon_platform_result': {'rc': 0, 'stdout': daemon},
                    'image_platform_result': {'rc': 0, 'stdout': raw},
                }, [])
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('image_platform_unavailable', result.stdout)
                self.assertEqual(calls, [])
                self.assertNotIn('TEMPLATE_OUTPUT_JSON=', result.stdout)
        result, calls = run_tasks([compare, require], {
            'daemon_platform_result': {'rc': 1, 'stdout': daemon},
            'image_platform_result': {'rc': 0, 'stdout': image},
        }, [])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('image_platform_unavailable', result.stdout)
        self.assertEqual(calls, [])

    def test_native_platform_normalization_aliases_and_variant_comparison(self):
        tasks = yaml.safe_load(PREPARATION.read_text())
        compare = named(tasks, 'Compare prepared image with actual Docker platform')
        for server, image, variant, code in (
            ('x86_64', 'AMD64', 'v1', 'matched'),
            ('aarch64', 'arm64', 'v8', 'matched'),
            ('armv7l', 'arm', 'v7', 'matched'),
            ('x86_64', 'arm64', 'v8', 'image_platform_mismatch'),
            ('armv7l', 'arm', 'v6', 'image_platform_mismatch'),
        ):
            with self.subTest(server=server, image=image, variant=variant):
                result, calls = run_tasks([compare, {'ansible.builtin.assert': {'that':
                    ['image_platform_comparison.code == expected_code']}}], {
                    'daemon_platform_result': {'rc': 0, 'stdout': json.dumps({'os': 'linux', 'architecture': server})},
                    'image_platform_result': {'rc': 0, 'stdout': json.dumps({'os': 'linux', 'architecture': image, 'variant': variant})},
                    'expected_code': code,
                }, [])
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(calls, [])

    def test_actual_preparation_cached_pulled_mismatch_and_unknown_before_mutations(self):
        tasks = yaml.safe_load(PREPARATION.read_text())[0]['block']
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
        preparation = text.index('- name: Prepare image through the shared authentication and platform boundary')
        for name in ('Mark source replacement transaction active',
                     'Converge the shared reviewed Compose deployment'):
            self.assertLess(preparation, text.index('- name: ' + name))
        self.assertLess(preparation, text.index('docker rm -f'))
        self.assertLess(text.index('- name: Prepare every reviewed Compose service image before workload changes'),
                        text.index('- name: Execute the reviewed Compose group through the shared transition'))
        self.assertIn('../tasks/container_image_prepare.yml', text)
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

    def test_grouped_authentication_is_per_service_and_never_anonymous_fallback(self):
        image = 'ghcr.io/proof/image@sha256:' + 'a' * 64
        private_value = 'private-registry-password-marker'
        for mode in ('valid', 'anonymous_with_auth', 'wrong_image', 'login_failed'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(prefix='grouped-auth-') as temporary:
                directory = Path(temporary)
                calls = directory / 'calls.jsonl'
                marker = directory / 'workload-changed'
                auth = {'host': 'ghcr.io', 'username': 'fixture', 'password': private_value}
                entries = {
                    'private': {'image': image, 'mode': 'credential', 'credential_id': 'credential', 'auth': auth},
                    'public': {'image': image, 'mode': 'anonymous', 'credential_id': None, 'auth': None},
                }
                if mode == 'anonymous_with_auth':
                    entries['public']['auth'] = auth
                if mode == 'wrong_image':
                    entries['private']['image'] = image.replace('a' * 64, 'b' * 64)
                secret = directory / 'registry-auth.json'
                secret.write_text(json.dumps({'contract_version': 'compose-registry-v1', 'services': entries}))
                tasks = yaml.safe_load(PREPARATION.read_text().replace('/secrets/registry-auth.json', str(secret)))
                docker = directory / 'docker'
                docker.write_text('''#!/usr/bin/env python3
import json, os, sys
with open(os.environ['OBSERVATION_CALLS'], 'a') as log:
    log.write(json.dumps({'argv': sys.argv[1:], 'config': os.environ.get('DOCKER_CONFIG')}) + '\\n')
if sys.argv[1] == 'login':
    sys.stdin.read()
    raise SystemExit(1 if os.environ['OBSERVATION_MODE'] == 'login_failed' else 0)
elif sys.argv[1] == 'logout':
    pass
elif sys.argv[1] == 'info':
    print(json.dumps({'os': 'linux', 'architecture': 'x86_64'}))
elif sys.argv[1:3] == ['image', 'inspect']:
    print(json.dumps({'os': 'linux', 'architecture': 'amd64', 'variant': 'v1'}))
else:
    raise SystemExit('unexpected Docker command')
''')
                docker.chmod(0o700)
                reviewed = {name: {key: entry[key] for key in ('mode', 'credential_id')}
                            for name, entry in entries.items()}
                selected_tasks = []
                for name in ('private', 'public'):
                    selected_tasks.append({'name': 'Select reviewed service', 'ansible.builtin.set_fact': {
                        'compose_image_service': name}})
                    selected_tasks.extend(tasks)
                selected_tasks.append({'name': 'Fixture workload mutation boundary',
                    'ansible.builtin.command': {'argv': ['touch', str(marker)]}})
                play = [{'hosts': 'all', 'gather_facts': False, 'vars': {
                    'app_image': image, 'app_compose_registry_access': reviewed,
                    'source_replacement_transaction_active': False, 'source_replacement_removed': False},
                    'tasks': selected_tasks}]
                path = directory / 'play.yml'
                path.write_text(yaml.safe_dump(play, sort_keys=False))
                result = subprocess.run(['ansible-playbook', '-i', '127.0.0.1,', '-c', 'local', str(path)],
                    env={**os.environ, 'PATH': str(directory) + ':' + os.environ['PATH'],
                         'OBSERVATION_CALLS': str(calls), 'OBSERVATION_MODE': mode},
                    capture_output=True, text=True, timeout=90)
                commands = [json.loads(line) for line in calls.read_text().splitlines()] if calls.exists() else []
                self.assertNotIn(private_value, result.stdout + result.stderr + calls.read_text() if calls.exists()
                                 else result.stdout + result.stderr)
                logins = [call for call in commands if call['argv'][0] == 'login']
                self.assertLessEqual(len(logins), 1)
                if mode == 'valid':
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertTrue(marker.exists())
                    self.assertEqual(len(logins), 1)
                    configs = {call['config'] for call in commands if call['argv'][:2] == ['image', 'inspect']}
                    # Inspect is read-only; credential-bearing commands retain private per-service custody.
                    self.assertEqual(configs, {None})
                    self.assertTrue(logins[0]['config'])
                    logout = [call for call in commands if call['argv'][0] == 'logout']
                    self.assertEqual(len(logout), 1)
                    self.assertEqual(logout[0]['config'], logins[0]['config'])
                    self.assertFalse(Path(logins[0]['config']).exists())
                else:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(marker.exists())
                    if mode in ('wrong_image', 'login_failed'):
                        self.assertFalse(any(call['argv'][:2] == ['image', 'inspect'] for call in commands))


if __name__ == '__main__':
    unittest.main()
