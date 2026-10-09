"""Local behavior of the unchanged native Template file-delivery procedure."""

from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
PLAYBOOK = ROOT / 'catalog/ansible/playbooks/materialize_template_files.yml'
PAYLOADS = (
    b'#!/bin/sh\n# private-template-marker\nprintf "{{ literal }} ${HOME} $HOME"\n',
    bytes(range(256)) + b'\x00private-binary-marker\r\n{{ raw }}${HOME}',
    b'public readable {{ literal }} ${HOME}\n',
    b'#!/bin/sh\n# preserved executable; never executed\n',
)


@contextmanager
def frozen_input():
    """Stage owned inputs separately from target and Ansible temporary effects."""
    with tempfile.TemporaryDirectory(prefix='materialize-files-') as temporary:
        directory = Path(temporary)
        staged = directory / 'staged'
        targets = directory / 'targets'
        staged.mkdir(mode=0o700)
        targets.mkdir(mode=0o700)
        sentinel = targets / 'unrelated-sentinel'
        sentinel.write_bytes(b'unrelated-private-sentinel')
        sentinel.chmod(0o600)
        records = []
        for index, (path, mode, payload) in enumerate(zip(
            ('bin/run.sh', 'assets/data.bin', 'config/public.txt', 'tools/public.sh'),
            ('0700', '0600', '0644', '0755'), PAYLOADS,
        )):
            source = f'source-{index:02d}'
            source_file = staged / source
            source_file.write_bytes(payload)
            source_file.chmod(0o400)
            records.append({
                'path': path, 'source': source, 'mode': mode,
                'size_bytes': len(payload), 'sha256': hashlib.sha256(payload).hexdigest(),
            })
        staged.chmod(0o500)
        args = {
            'template_source_directory': str(staged),
            'template_supplied_files': records,
            'template_entrypoint': 'bin/run.sh',
        }
        try:
            yield directory, targets, sentinel, args
        finally:
            staged.chmod(0o700)


class MaterializeTemplateFilesTests(unittest.TestCase):
    def invoke(self, directory, targets, args, foreign_parent=False):
        parameters = directory / 'inputs.json'
        parameters.write_text(json.dumps(args))
        parameters.chmod(0o400)
        environment = {
            **os.environ,
            'TMPDIR': str(targets),
            'ANSIBLE_LOCAL_TEMP': str(directory / 'ansible-local'),
            'ANSIBLE_REMOTE_TEMP': str(directory / 'ansible-remote'),
        }
        playbook = PLAYBOOK
        if foreign_parent:
            procedure = yaml.safe_load(PLAYBOOK.read_text())
            preparation = next(task for task in procedure[0]['tasks'] if 'block' in task)['block']
            parent = next(task for task in preparation
                          if task.get('name') == 'Validate the optional existing private target parent')
            index = next(index for index, task in enumerate(parent['block'])
                         if task.get('register') == 'template_delivery_parent_stats')
            parent['block'].insert(index + 1, {
                'name': 'Model only a foreign final-parent UID on actual metadata',
                'ansible.builtin.set_fact': {'template_delivery_parent_stats':
                    "{% set rows = template_delivery_parent_stats.results %}"
                    "{{ template_delivery_parent_stats | combine({'results': rows[:-1] + "
                    "[rows[-1] | combine({'stat': rows[-1].stat | combine({'uid': "
                    + str(os.getuid() + 1) + "})})]}) }}"},
                'no_log': True,
            })
            playbook = directory / 'foreign-parent.yml'
            playbook.write_text(yaml.safe_dump(procedure, sort_keys=False))
        result = subprocess.run(
            ['ansible-playbook', '-i', '127.0.0.1,', '-c', 'local',
             str(playbook), '-e', '@' + str(parameters)],
            env=environment, capture_output=True, text=True, timeout=120,
        )
        messages = []
        for line in result.stdout.splitlines():
            if line.strip().startswith('"msg": "TEMPLATE_OUTPUT_JSON='):
                message = json.loads('{' + line.strip().rstrip(',') + '}')['msg']
                messages.append(json.loads(message.split('=', 1)[1]))
        self.assertEqual(len(messages), 1, result.stdout + result.stderr)
        self.assertEqual(set(messages[0]), {'template_file_delivery'})
        output = result.stdout + result.stderr
        for private_marker in ('private-template-marker', 'private-binary-marker',
                               'unrelated-private-sentinel'):
            self.assertNotIn(private_marker, output)
        return result, messages[0]['template_file_delivery']

    def assert_sentinel(self, sentinel):
        self.assertEqual(sentinel.read_bytes(), b'unrelated-private-sentinel')
        self.assertEqual(stat.S_IMODE(sentinel.lstat().st_mode), 0o600)

    def test_private_parent_confines_fresh_child_and_preserves_standalone_default(self):
        for selected in (True, False):
            with self.subTest(parent=selected), frozen_input() as (directory, targets, sentinel, args):
                parent = targets / 'private-parent'
                if selected:
                    parent.mkdir(mode=0o700)
                    args['template_workspace_parent'] = str(parent)
                result, delivery = self.invoke(directory, targets, args)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(delivery['outcome'], 'delivered')
                workspace = Path(delivery['workspace'])
                self.assertEqual(workspace.parent, parent if selected else targets)
                self.assertTrue(workspace.name.startswith('opsctl-template-'))
                self.assertEqual(stat.S_IMODE(workspace.stat().st_mode), 0o700)
                for record, payload in zip(args['template_supplied_files'], PAYLOADS):
                    path = workspace / record['path']
                    self.assertEqual(path.read_bytes(), payload)
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), int(record['mode'], 8))
                    original = Path(args['template_source_directory']) / record['source']
                    self.assertEqual(original.read_bytes(), payload)
                    self.assertEqual(stat.S_IMODE(original.stat().st_mode), 0o400)
                self.assertEqual(delivery['files'], [
                    {key: record[key] for key in ('path', 'mode', 'size_bytes', 'sha256')}
                    for record in args['template_supplied_files']])
                self.assert_sentinel(sentinel)

    def test_private_parent_refusals_precede_allocation(self):
        """Foreign ownership is a finite metadata substitution, not privileged chown."""
        for case in ('unsafe', 'missing', 'link', 'foreign'):
            with self.subTest(case=case), frozen_input() as (directory, targets, sentinel, args):
                parent = targets / 'private-parent'
                if case != 'missing':
                    parent.mkdir(mode=0o700)
                if case == 'unsafe':
                    parent.chmod(0o777)
                if case == 'link':
                    link = directory / 'linked-parent'
                    link.symlink_to(parent)
                    args['template_workspace_parent'] = str(link)
                else:
                    args['template_workspace_parent'] = str(parent)
                before = list(targets.iterdir())
                result, delivery = self.invoke(directory, targets, args, foreign_parent=case == 'foreign')
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertEqual(delivery['outcome'], 'refused')
                self.assertEqual(delivery['cleanup'], 'not_allocated')
                self.assertIsNone(delivery['workspace'])
                self.assertEqual(delivery['files'], [])
                self.assertEqual(list(targets.iterdir()), before)
                if parent.exists():
                    self.assertEqual(list(parent.iterdir()), [])
                for record, payload in zip(args['template_supplied_files'], PAYLOADS):
                    self.assertEqual((Path(args['template_source_directory']) / record['source']).read_bytes(), payload)
                self.assert_sentinel(sentinel)

    def test_nested_binary_literal_files_preserve_order_bytes_modes_and_checksums(self):
        with frozen_input() as (directory, targets, sentinel, args):
            result, delivery = self.invoke(directory, targets, args)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(delivery['outcome'], 'delivered')
            self.assertEqual(delivery['reason'], 'delivered')
            self.assertIsNone(delivery['original_reason'])
            self.assertEqual(delivery['cleanup'], 'not_required')
            self.assertEqual(delivery['entrypoint'], 'bin/run.sh')
            workspace = Path(delivery['workspace'])
            self.assertEqual(workspace.parent, targets)
            self.assertTrue(workspace.name.startswith('opsctl-template-'))
            self.assertEqual(stat.S_IMODE(workspace.lstat().st_mode), 0o700)
            expected = []
            for supplied, payload in zip(args['template_supplied_files'], PAYLOADS):
                delivered = workspace / supplied['path']
                self.assertFalse(delivered.is_symlink())
                self.assertTrue(delivered.is_file())
                self.assertEqual(delivered.read_bytes(), payload)
                self.assertEqual(stat.S_IMODE(delivered.lstat().st_mode), int(supplied['mode'], 8))
                self.assertEqual(stat.S_IMODE(delivered.parent.lstat().st_mode), 0o700)
                expected.append({key: supplied[key] for key in ('path', 'mode', 'size_bytes', 'sha256')})
            self.assertEqual(delivery['files'], expected)
            for supplied, payload in zip(args['template_supplied_files'], PAYLOADS):
                staged = Path(args['template_source_directory']) / supplied['source']
                self.assertEqual(staged.read_bytes(), payload)
                self.assertEqual(stat.S_IMODE(staged.stat().st_mode), 0o400)
            self.assert_sentinel(sentinel)

    def test_unsafe_inputs_and_sources_refuse_before_target_allocation(self):
        for case in ('checksum', 'path', 'overlap', 'symlink', 'missing-entrypoint',
                     '0666', '0620', '04755', '01700'):
            with self.subTest(case=case), frozen_input() as (directory, targets, sentinel, args):
                expected = 'invalid_inputs'
                if case == 'checksum':
                    args['template_supplied_files'][0]['sha256'] = '0' * 64
                    expected = 'source_mismatch'
                elif case == 'path':
                    args['template_supplied_files'][1]['path'] = '../escape'
                elif case == 'overlap':
                    args['template_supplied_files'][0]['path'] = 'bin'
                    args['template_supplied_files'][1]['path'] = 'bin/data.bin'
                    args['template_entrypoint'] = 'bin'
                elif case == 'symlink':
                    links = directory / 'symlink-staged'
                    links.mkdir(mode=0o700)
                    for record in args['template_supplied_files']:
                        (links / record['source']).symlink_to(
                            Path(args['template_source_directory']) / record['source'],
                        )
                    args['template_source_directory'] = str(links)
                    expected = 'source_unavailable'
                elif case == 'missing-entrypoint':
                    args['template_entrypoint'] = 'bin/missing.sh'
                else:
                    args['template_supplied_files'][0]['mode'] = case
                result, delivery = self.invoke(directory, targets, args)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertEqual(delivery['outcome'], 'refused')
                self.assertEqual(delivery['reason'], expected)
                self.assertEqual(delivery['original_reason'], expected)
                self.assertEqual(delivery['cleanup'], 'not_allocated')
                self.assertIsNone(delivery['workspace'])
                self.assertEqual(delivery['files'], [])
                self.assertEqual(list(targets.iterdir()), [sentinel])
                self.assert_sentinel(sentinel)

    def test_real_second_copy_failure_removes_only_owned_workspace(self):
        with frozen_input() as (directory, targets, sentinel, args):
            args['template_supplied_files'][1]['path'] = 'x' * 256
            self.assertEqual(len(args['template_supplied_files'][1]['path'].encode()), 256)
            result, delivery = self.invoke(directory, targets, args)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertEqual(delivery['outcome'], 'refused')
            self.assertEqual(delivery['reason'], 'delivery_failed')
            self.assertEqual(delivery['original_reason'], 'delivery_failed')
            self.assertEqual(delivery['cleanup'], 'removed')
            self.assertEqual(delivery['entrypoint'], 'bin/run.sh')
            self.assertIsNone(delivery['workspace'])
            self.assertEqual(delivery['files'], [])
            copy_output = result.stdout.split(
                'TASK [Copy frozen original bytes', 1,
            )[1].split('TASK [Preserve the original', 1)[0]
            self.assertLess(copy_output.index('changed:'), copy_output.index('failed:'))
            self.assertIn('Filename too long', result.stdout + result.stderr)
            self.assertEqual(list(targets.iterdir()), [sentinel])
            self.assert_sentinel(sentinel)


if __name__ == '__main__':
    unittest.main()
