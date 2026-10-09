"""Confined real-file collection and production-task publication boundaries."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'catalog/ansible/scripts/compose_selected_file_observe.py'
INCLUDE = ROOT / 'catalog/ansible/tasks/compose_selected_file_observe.yml'
PUBLISH = ROOT / 'catalog/ansible/tasks/compose_publish.yml'
SPEC = importlib.util.spec_from_file_location('compose_selected_file_observer', HELPER)
OBSERVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(OBSERVER)


class ComposeSelectedFileObserveTests(unittest.TestCase):
    def test_confined_metadata_missing_links_permissions_and_nonregular_files(self):
        with tempfile.TemporaryDirectory(prefix='selected-native-') as temporary:
            workspace = Path(temporary) / 'workspace'
            workspace.mkdir()
            (workspace / 'nested').mkdir()
            payload = b'synthetic-content-not-for-output\x00\xff\n'
            regular = workspace / 'nested/regular'
            regular.write_bytes(payload)
            regular.chmod(0o4755)
            unreadable = workspace / 'unreadable'
            unreadable.write_bytes(payload)
            unreadable.chmod(0)
            (workspace / 'leaf-link').symlink_to(regular)
            (workspace / 'parent-link').symlink_to(regular.parent, target_is_directory=True)
            os.mkfifo(workspace / 'pipe')
            sentinel = Path(temporary) / 'sentinel'
            sentinel.write_bytes(b'unrelated-sentinel')
            sentinel.chmod(0o640)
            paths = ['nested/regular', 'missing', 'missing-parent/leaf', 'leaf-link',
                     'parent-link/regular', 'unreadable', 'pipe']
            descriptors = len(os.listdir('/proc/self/fd'))
            try:
                result = OBSERVER.collect(str(workspace), paths)
            finally:
                unreadable.chmod(0o600)
            self.assertEqual(len(os.listdir('/proc/self/fd')), descriptors)
            rows = result['selected_file_observations']
            self.assertEqual([row['path'] for row in rows], paths)
            self.assertEqual(rows[0], {
                'path': paths[0], 'presence': 'present', 'size_bytes': len(payload),
                'mode': '4755', 'sha256': hashlib.sha256(payload).hexdigest(), 'reason': None,
            })
            self.assertEqual([row['reason'] for row in rows], [
                None, 'missing', 'missing', 'unsafe_path', 'unsafe_path',
                'permission_denied', 'not_regular',
            ])
            self.assertEqual([row['presence'] for row in rows], [
                'present', 'absent', 'absent', 'unknown', 'unknown', 'unknown', 'unknown',
            ])
            for row in rows[1:]:
                self.assertIsNone(row['size_bytes'])
                self.assertIsNone(row['mode'])
                self.assertIsNone(row['sha256'])
            self.assertFalse(result['selected_file_observation_complete'])
            self.assertEqual(OBSERVER.collect(str(workspace), []), {
                'selected_file_observations': [], 'selected_file_observation_complete': False,
            })
            self.assertEqual(regular.read_bytes(), payload)
            self.assertEqual(stat.S_IMODE(regular.stat().st_mode), 0o4755)
            self.assertEqual(sentinel.read_bytes(), b'unrelated-sentinel')
            self.assertEqual(stat.S_IMODE(sentinel.stat().st_mode), 0o640)
            self.assertNotIn('synthetic-content-not-for-output', json.dumps(result))

    def test_entire_invalid_membership_refuses_before_filesystem_access(self):
        invalid_paths = ['', '../escape', '/absolute', 'a//b', 'a/./b', 'a\\b',
                         'line\nfeed', '\x00', 'é' * 129]
        with patch.object(OBSERVER.os, 'open', side_effect=AssertionError('disk access')) as opened:
            for path in invalid_paths:
                with self.subTest(path=repr(path)), self.assertRaises(ValueError):
                    OBSERVER.collect('/owned/workspace', ['valid', path])
            for selection in [['same', 'same'], [str(index) for index in range(33)],
                              ('tuple',), True, 'string', [False]]:
                with self.subTest(selection_type=type(selection).__name__), self.assertRaises(ValueError):
                    OBSERVER.collect('/owned/workspace', selection)
            opened.assert_not_called()

    def test_real_mutations_refuse_without_reading_growth_or_leaking_descriptors(self):
        native_read = OBSERVER.os.read
        with tempfile.TemporaryDirectory(prefix='selected-races-') as temporary:
            for kind in ['leaf-replace', 'ancestor-replace', 'growth']:
                with self.subTest(kind=kind):
                    workspace = Path(temporary) / kind
                    parent = workspace / 'parent'
                    parent.mkdir(parents=True)
                    selected = parent / 'selected'
                    selected.write_bytes(b'x' * 65536)
                    counts = {'bytes': 0, 'triggered': False}
                    descriptors = len(os.listdir('/proc/self/fd'))

                    def racing_read(descriptor, size):
                        chunk = native_read(descriptor, size)
                        counts['bytes'] += len(chunk)
                        if not counts['triggered']:
                            counts['triggered'] = True
                            if kind == 'leaf-replace':
                                selected.rename(parent / 'original')
                                selected.write_bytes(b'replacement')
                            elif kind == 'ancestor-replace':
                                parent.rename(workspace / 'original-parent')
                                parent.mkdir()
                                selected.write_bytes(b'replacement')
                            else:
                                with selected.open('ab') as stream:
                                    stream.write(b'growth')
                        return chunk

                    with patch.object(OBSERVER.os, 'read', side_effect=racing_read):
                        result = OBSERVER.collect(str(workspace), ['parent/selected'])
                    self.assertEqual(counts['bytes'], 65536)
                    self.assertEqual(len(os.listdir('/proc/self/fd')), descriptors)
                    self.assertEqual(result['selected_file_observations'], [{
                        'path': 'parent/selected', 'presence': 'unknown', 'size_bytes': None,
                        'mode': None, 'sha256': None, 'reason': 'changed_during_collection',
                    }])
                    self.assertFalse(result['selected_file_observation_complete'])

    def test_exact_file_and_total_budgets_keep_remaining_members_without_reads(self):
        native_read = OBSERVER.os.read
        with tempfile.TemporaryDirectory(prefix='selected-budgets-') as temporary:
            workspace = Path(temporary)
            for index in range(4):
                (workspace / str(index)).write_bytes(b'x' * 262144)
            for name in ['remaining', 'later']:
                (workspace / name).write_bytes(b'x')
            (workspace / 'oversized').write_bytes(b'x' * 262145)
            counts = {'bytes': 0}

            def counted_read(descriptor, size):
                self.assertLessEqual(size, 65536)
                chunk = native_read(descriptor, size)
                counts['bytes'] += len(chunk)
                return chunk

            with patch.object(OBSERVER.os, 'read', side_effect=counted_read):
                oversized = OBSERVER.collect(str(workspace), ['oversized'])
                self.assertEqual(counts['bytes'], 0)
                paths = ['0', '1', '2', '3', 'remaining', 'later']
                result = OBSERVER.collect(str(workspace), paths)
            self.assertEqual(counts['bytes'], 1048576)
            self.assertEqual(oversized['selected_file_observations'][0]['reason'], 'file_limit_exceeded')
            rows = result['selected_file_observations']
            self.assertEqual([row['path'] for row in rows], paths)
            self.assertTrue(all(row['presence'] == 'present' for row in rows[:4]))
            self.assertEqual([row['reason'] for row in rows[-2:]], ['total_limit_exceeded'] * 2)
            self.assertFalse(result['selected_file_observation_complete'])

    def invoke_tasks(self, root, workspace, case, parameters):
        """Execute loaded production tasks; only stated failure inputs are modeled."""
        tasks = yaml.safe_load(INCLUDE.read_text())
        publisher = yaml.safe_load(PUBLISH.read_text())
        if case == 'unavailable':
            tasks[-1]['block'][0]['ansible.builtin.script']['executable'] = '/absent-python'
        if case == 'malformed':
            tasks[-1]['block'].insert(1, {
                'name': 'Model malformed returned stdout after actual helper execution',
                'ansible.builtin.set_fact': {'compose_selected_file_read': {'stdout': '{invalid-json'}},
            })
        if case in ['deploy', 'remove']:
            tasks = []
        facts = {
            'compose_action': 'inspect', 'compose_workspace': str(workspace),
            'compose_project_name': 'owned-observation', 'compose_phase': 'compose:complete',
            'compose_outcome': 'succeeded', 'compose_observation_complete': True,
            'compose_ready': True, 'nonsecret_files': ['nested/regular', 'missing'],
            **parameters,
        }
        playbooks = root / case / 'playbooks'
        playbooks.mkdir(parents=True)
        (playbooks.parent / 'scripts').symlink_to(HELPER.parent)
        invocation = playbooks / 'actual-tasks.yml'
        invocation.write_text(yaml.safe_dump([{
            'hosts': 'all', 'gather_facts': False, 'become': False,
            'vars': facts, 'tasks': tasks + publisher,
        }], sort_keys=False))
        result = subprocess.run(
            ['ansible-playbook', '-i', '127.0.0.1,', '-c', 'local', str(invocation)],
            capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(result.returncode, 2 if case == 'unicode-overflow' else 0,
                         result.stdout + result.stderr)
        lines = [line.strip() for line in result.stdout.splitlines()
                 if line.strip().startswith('"msg": "TEMPLATE_OUTPUT_JSON=')]
        self.assertEqual(len(lines), 1, result.stdout)
        message = json.loads('{' + lines[0].rstrip(',') + '}')['msg']
        serialized = message.split('=', 1)[1]
        self.assertTrue(serialized.isascii())
        self.assertLessEqual(len(serialized.encode('utf-8')), 262144)
        self.assertNotIn('synthetic-content-not-for-output', result.stdout + result.stderr)
        return json.loads(serialized)['compose'], facts

    def test_production_membership_failures_wire_overflow_and_mutation_exclusion(self):
        with tempfile.TemporaryDirectory(prefix='selected-tasks-') as temporary:
            root = Path(temporary)
            workspace = root / 'workspace'
            (workspace / 'nested').mkdir(parents=True)
            source = workspace / 'nested/regular'
            payload = b'synthetic-content-not-for-output'
            source.write_bytes(payload)
            source.chmod(0o640)
            sentinel = root / 'sentinel'
            sentinel.write_bytes(b'unrelated-sentinel')
            sentinel.chmod(0o640)
            stale = [{'path': 'stale', 'presence': 'unknown', 'size_bytes': None,
                      'mode': None, 'sha256': None, 'reason': 'read_failed'}]
            cases = [
                ('valid', workspace, {}), ('empty', workspace, {'nonsecret_files': []}),
                ('unavailable', workspace, {}), ('malformed', workspace, {}),
                ('missing-workspace', root / 'absent-workspace', {}),
                ('unicode-overflow', workspace, {'compose_observed_services': [{'name': 'é' * 62000}]}),
                ('deploy', workspace, {'compose_action': 'deploy',
                                      'compose_selected_file_observations': stale,
                                      'compose_selected_file_observation_complete': True}),
                ('remove', workspace, {'compose_action': 'remove',
                                      'compose_selected_file_observations': stale,
                                      'compose_selected_file_observation_complete': True}),
            ]
            for case, selected_workspace, parameters in cases:
                with self.subTest(case=case):
                    composed, facts = self.invoke_tasks(root, selected_workspace, case, parameters)
                    if case in ['deploy', 'remove']:
                        self.assertNotIn('selected_file_observations', composed)
                        self.assertNotIn('selected_file_observation_complete', composed)
                    else:
                        rows = composed['selected_file_observations']
                        self.assertEqual([row['path'] for row in rows], facts['nonsecret_files'])
                        self.assertEqual(composed['files_written'], [])
                        if case == 'valid':
                            self.assertTrue(composed['selected_file_observation_complete'])
                            self.assertEqual(rows[0]['sha256'], hashlib.sha256(payload).hexdigest())
                            self.assertEqual(rows[0]['mode'], '0640')
                            self.assertEqual(rows[1]['presence'], 'absent')
                        else:
                            self.assertFalse(composed['selected_file_observation_complete'])
                            reason = 'result_limit_exceeded' if case == 'unicode-overflow' else 'read_failed'
                            for row in rows:
                                self.assertEqual(row['presence'], 'unknown')
                                self.assertEqual(row['reason'], reason)
                                self.assertIsNone(row['size_bytes'])
                                self.assertIsNone(row['mode'])
                                self.assertIsNone(row['sha256'])
                    if case == 'unicode-overflow':
                        self.assertEqual(composed['outcome'], 'unknown')
                        self.assertEqual(composed['reason'], 'compose_observation_limit')
                        self.assertFalse(composed['observation_complete'])
                        self.assertIsNone(composed['ready'])
                        self.assertIsNone(composed['observed_at'])
                    else:
                        self.assertTrue(composed['observation_complete'])
                        self.assertEqual(composed['outcome'], 'succeeded')
                        if case != 'remove':
                            self.assertTrue(composed['ready'])
                    self.assertEqual(source.read_bytes(), payload)
                    self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o640)
                    self.assertEqual(sentinel.read_bytes(), b'unrelated-sentinel')
                    self.assertEqual(stat.S_IMODE(sentinel.stat().st_mode), 0o640)


if __name__ == '__main__':
    unittest.main()
