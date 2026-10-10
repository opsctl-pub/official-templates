"""Actual trusted delivery and host commands on disposable local test hosts."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from uuid import uuid4

import yaml


CATALOG = Path(__file__).resolve().parents[1] / 'catalog/ansible'


class RunTemplateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='host-template-contract-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.stage = self.root / 'staged'
        self.stage.mkdir(mode=0o700)
        self.output = self.root / 'host-change'
        self.workspace = self.root / 'workspace-observed'
        self.sentinel = self.root / 'sentinel'
        self.sentinel.write_bytes(b'unchanged unrelated file')

    def invoke(self, engine, files, *, target=None):
        """Run the actual procedure, not copied or rewritten task bodies."""
        supplied = []
        for index, (path, mode, contents) in enumerate(files):
            name = 'source-%02d' % index
            value = contents.encode()
            source = self.stage / name
            source.write_bytes(value)
            source.chmod(0o600)
            supplied.append({'source': name, 'path': path, 'mode': mode,
                'size_bytes': len(value), 'sha256': hashlib.sha256(value).hexdigest()})
        inputs = json.dumps({'opsctl_inputs': {'destination': str(self.output),
            'workspace_marker': str(self.workspace), 'literal': '${HOME} {{ literal }}'}}).encode()
        (self.stage / 'template-inputs.json').write_bytes(inputs)
        (self.stage / 'template-inputs.json').chmod(0o600)
        targets = [] if target is None else [target]
        if target is not None:
            (self.stage / target['credential_file']).write_bytes(b'synthetic selected private key')
            (self.stage / target['credential_file']).chmod(0o600)
        carrier = {'operation_id': str(uuid4()), 'controller_server_id': str(uuid4()),
            'source_digest': 'a' * 64, 'input_digest': hashlib.sha256(inputs).hexdigest(),
            'payload_engine': engine, 'entrypoint': files[0][0], 'targets': targets,
            'timeout_seconds': 30, 'staging_directory': str(self.stage),
            'supplied_files': supplied}
        variables = self.root / 'variables.json'
        variables.write_text(json.dumps({'template_execution': carrier,
            'template_source_directory': str(self.stage), 'template_supplied_files': supplied,
            'template_entrypoint': files[0][0], 'ansible_python_interpreter': sys.executable}))
        variables.chmod(0o600)
        inventory = self.root / 'management-inventory'
        inventory.write_text('127.0.0.1 ansible_connection=local\n')
        result = subprocess.run(['ansible-playbook', '-i', str(inventory),
            str(CATALOG / 'playbooks/run_template.yml'), '-e', '@' + str(variables)],
            env={**os.environ, 'ANSIBLE_LOCAL_TEMP': str(self.root / 'ansible-local'),
                 'ANSIBLE_REMOTE_TEMP': str(self.root / 'ansible-remote')},
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=90)
        self.assertEqual(self.sentinel.read_bytes(), b'unchanged unrelated file')
        for row in supplied:
            self.assertEqual(hashlib.sha256((self.stage / row['source']).read_bytes()).hexdigest(),
                             row['sha256'])
        return result

    def test_bash_changes_host_with_sibling_and_exact_inputs_then_cleans_workspace(self):
        script = '''#!/bin/bash
set -eu
python3 - "$OPSCTL_INPUTS_FILE" <<'PY'
import json, os, pathlib, sys
inputs = json.loads(pathlib.Path(sys.argv[1]).read_text())['opsctl_inputs']
assert inputs['literal'] == '${HOME} {{ literal }}'
assert pathlib.Path('config/value.txt').read_text() == 'sibling literal'
assert pathlib.Path(sys.argv[1]).stat().st_mode & 0o777 == 0o600
pathlib.Path(inputs['destination']).write_text('changed on execution host')
pathlib.Path(inputs['workspace_marker']).write_text(os.getcwd())
PY
'''
        result = self.invoke('bash', [('bin/main.sh', '0755', script),
                                     ('config/value.txt', '0600', 'sibling literal')])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.output.read_text(), 'changed on execution host')
        self.assertFalse(Path(self.workspace.read_text()).exists())

    def test_failed_bash_exit_fails_job_and_still_cleans_workspace(self):
        script = '''#!/bin/bash
python3 - "$OPSCTL_INPUTS_FILE" <<'PY'
import json, os, pathlib, sys
inputs = json.loads(pathlib.Path(sys.argv[1]).read_text())['opsctl_inputs']
pathlib.Path(inputs['workspace_marker']).write_text(os.getcwd())
PY
exit 37
'''
        result = self.invoke('bash', [('main.sh', '0700', script)])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('exited with code 37', result.stdout)
        self.assertFalse(Path(self.workspace.read_text()).exists())

    def test_user_ansible_executes_on_controller_with_selected_private_inventory(self):
        target = {'server_id': str(uuid4()), 'address': '127.0.0.1', 'port': 22,
            'username': 'selected-user', 'credential_file': 'selected.key',
            'host_public_key': 'ssh-ed25519 synthetic-observed-public-key'}
        content = yaml.safe_dump([{'hosts': 'all', 'connection': 'local',
            'gather_facts': False, 'tasks': [
                {'ansible.builtin.command': {'argv': ['python3', '-c',
                    "import json,pathlib,sys; value=json.loads(pathlib.Path(sys.argv[1]).read_text())['opsctl_inputs']; pathlib.Path(value['destination']).write_text(value['literal'])",
                    '{{ playbook_dir }}/template-inputs.json'],
                    'expand_argument_vars': False}},
                {'ansible.builtin.copy': {'dest': '{{ opsctl_inputs.workspace_marker }}',
                    'content': "{{ playbook_dir }}"}},
                {'ansible.builtin.assert': {'that': [
                    "ansible_user == 'selected-user'",
                    "'StrictHostKeyChecking=yes' in ansible_ssh_common_args",
                    "lookup('file', playbook_dir + '/selected.key') == 'synthetic selected private key'",
                    "'synthetic-observed-public-key' in lookup('file', playbook_dir + '/known_hosts')"]}},
            ]}], sort_keys=False)
        result = self.invoke('ansible', [('main.yml', '0600', content)], target=target)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.output.read_text(), '${HOME} {{ literal }}')
        self.assertFalse(Path(self.workspace.read_text()).exists())
        self.assertNotIn('synthetic selected private key', result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
