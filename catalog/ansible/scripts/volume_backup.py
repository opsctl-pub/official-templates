#!/usr/bin/env python3
"""Offline restic file copy using only an existing user-owned S3 bucket."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
from urllib.parse import quote
import re
import shlex
import stat
import subprocess
import sys
from datetime import datetime, timezone


RESTIC = 'restic/restic@sha256:136600b6ff6843d61d355f7f71f460a166429f35de6fd11b568fece3c9a4d510'
RCLONE = 'rclone/rclone@sha256:34c729127386abec1c610b2aa024e39b4498dc2b4a72a0798ae21fbdc1b0493b'
DIGEST = re.compile(r'^[a-f0-9]{64}$')
NAME = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.-]{0,254}$')


def now():
    return datetime.now(timezone.utc).isoformat()


def command(argv, *, check=True):
    """Native errors remain private; only plain bounded facts leave this process."""
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True,
                            timeout=3600, check=False)
    if len(result.stdout) > 4 * 1024 * 1024 or check and result.returncode:
        raise ValueError('native_command_incomplete')
    return result


def docker(*argv, check=True):
    return command(['docker', *argv], check=check)


def native_volume(expected):
    result = docker('volume', 'inspect', expected['name'], check=False)
    if result.returncode:
        raise ValueError('native_identity_unavailable')
    rows = json.loads(result.stdout)
    if len(rows) != 1:
        raise ValueError('native_identity_unavailable')
    volume = rows[0]
    if (volume['Name'] != expected['name'] or volume['Driver'] != 'local'
            or volume.get('Scope') != 'local' or volume.get('Options')
            or expected['created_at'] is not None and volume['CreatedAt'] != expected['created_at']
            or expected['labels'] is not None and volume.get('Labels') != expected['labels']
            or expected['birth_marker'] is not None
            and (volume.get('Labels') or {}).get('io.opsctl.compose.birth') != expected['birth_marker']):
        raise ValueError('native_identity_changed')
    return volume


def require_zero_users(name, own=None):
    users = docker('ps', '-aq', '--no-trunc', '--filter', 'volume=' + name).stdout.decode().split()
    if set(users) - ({own} if own else set()):
        raise ValueError('native_users_present')


def snapshot_record(item, repository_id):
    identity = item['id']
    if not isinstance(identity, str) or not DIGEST.fullmatch(identity):
        raise ValueError('snapshot_identity_unavailable')
    size = (item.get('summary') or {}).get('total_bytes_processed')
    return {'repository_id': repository_id, 'snapshot_id': identity, 'time': item['time'],
            'verified_at': None, 'archive_sha256': None,
            'logical_bytes': size if type(size) is int and size >= 0 else None,
            'ready': False, 'consistency': 'offline_file_copy_no_application_consistency_guarantee'}


def prepare_material(directory, location):
    """Only this procedure translates private material into the pinned tool's files."""
    values = json.loads((directory / 'backup-credentials.json').read_bytes())
    required = {'access_key_id', 'secret_access_key', 'repository_password'}
    if (not required <= set(values) or set(values) - required - {'session_token'}
            or any(type(value) is not str or not value
                   or any(char in value for char in ('\r', '\n', '\x00')) for value in values.values())):
        raise ValueError('private_material_unavailable')
    environment = {
        'RCLONE_CONFIG_OPSCTL_TYPE': 's3', 'RCLONE_CONFIG_OPSCTL_PROVIDER': 'Other',
        'RCLONE_CONFIG_OPSCTL_ENDPOINT': location['endpoint'],
        'RCLONE_CONFIG_OPSCTL_REGION': location['region'],
        'RCLONE_CONFIG_OPSCTL_ACCESS_KEY_ID': values['access_key_id'],
        'RCLONE_CONFIG_OPSCTL_SECRET_ACCESS_KEY': values['secret_access_key'],
        'RCLONE_CONFIG_OPSCTL_NO_CHECK_BUCKET': 'true', 'RCLONE_CONFIG_OPSCTL_ENV_AUTH': 'false',
        'RESTIC_PASSWORD_FILE': '/run/private/repository-password',
    }
    if 'session_token' in values:
        environment['RCLONE_CONFIG_OPSCTL_SESSION_TOKEN'] = values['session_token']
    files = {'repository-password': values['repository_password'].encode()}
    if location['ca_pem'] is not None:
        files['backup-ca.pem'] = location['ca_pem'].encode()
        environment['RCLONE_CA_CERT'] = '/run/private/backup-ca.pem'
    if (not location['endpoint'].startswith('https://')
            or any(any(char in value for char in ('\r', '\n', '\x00')) for value in environment.values())):
        raise ValueError('storage_environment_unavailable')
    files['backup.env'] = ''.join(key + '=' + value + '\n' for key, value in environment.items()).encode()
    for name, content in files.items():
        descriptor = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'wb') as target:
            target.write(content)


def recovery_kit(location, snapshot, version):
    """Portable secret-free recovery is a documented method result, not API tool logic."""
    uri = 's3:' + location['endpoint'] + '/' + location['bucket'] + '/' + quote(location['prefix'], safe='/')
    tool = 'restic -o s3.region=' + shlex.quote(location['region'])
    if location['ca_pem'] is not None:
        tool += ' --cacert USER_CA_FILE'
    identity = snapshot['snapshot_id']
    return {**location, 'method': 'restic_volume_copy_v1', 'restic_version': version,
        'repository_id': snapshot['repository_id'], 'snapshot_id': identity,
        'archive_sha256': snapshot['archive_sha256'], 'archive_path': '/data', 'instructions': [
            'Use restic ' + version + ' and sha256sum in a shell supporting pipefail.',
            'Supply independently retained password through RESTIC_PASSWORD_FILE and authorized AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY (plus session token when required).',
            'If ca_pem is supplied save it as USER_CA_FILE. Preserve verified TLS; never disable certificate checking.',
            'export RESTIC_REPOSITORY=' + shlex.quote(uri),
            tool + ' cat config # require the exact repository_id above',
            'set -o pipefail; ' + tool + ' dump ' + identity + ':/data / | sha256sum # require archive_sha256 above',
            tool + ' restore ' + identity + ':/data --target NEW_EMPTY_DIRECTORY --verify',
            'Use only a new empty destination. No OpsCtl database is needed; attachment, cutover and application consistency are separate.',
        ]}


def close_idle_tool(previous, repository_uri):
    """Close only this admitted predecessor's idle tool and exact private files."""
    name = 'opsctl-backup-' + previous
    found = docker('container', 'inspect', name, check=False)
    if found.returncode:
        return
    native = json.loads(found.stdout)[0]
    if (native['Config']['Image'] != RESTIC
            or native['Config']['Labels'].get('io.opsctl.backup.operation') != previous
            or 'RESTIC_REPOSITORY=' + repository_uri not in native['Config']['Env']):
        raise ValueError('interrupted_tool_changed')
    if native['State']['Running']:
        processes = docker('top', name, '-eo', 'args').stdout.decode().splitlines()[1:]
        if [line.strip() for line in processes] != ['sleep 86400']:
            raise ValueError('interrupted_tool_still_executing')
    private = [item['Source'] for item in native['Mounts']
               if item['Type'] == 'bind' and item['Destination'] == '/run/private']
    if len(private) != 1:
        raise ValueError('interrupted_private_files_unavailable')
    directory = Path(private[0])
    try:
        metadata = directory.lstat()
    except FileNotFoundError:
        metadata = None
    if metadata is not None and (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or json.loads((directory / 'intent.json').read_bytes())['operation_id'] != previous):
        raise ValueError('interrupted_private_files_changed')
    docker('rm', '-f', native['Id'])
    if metadata is None:
        return
    for filename in ('backup.env', 'backup-credentials.json', 'repository-password', 'backup-ca.pem', 'intent.json', 'rclone'):
        path = directory / filename
        if not path.exists():
            continue
        if not stat.S_ISREG(path.lstat().st_mode):
            raise ValueError('interrupted_private_file_changed')
        path.unlink()
    directory.rmdir()


def execute(inputs, directory, result):
    """The tool mount and native exclusion span the entire copy and verification."""
    operation = inputs['operation_id']
    if not re.fullmatch(r'[a-f0-9-]{36}', operation):
        raise ValueError('operation_identity_unavailable')
    action = inputs['action']
    if action not in {'init', 'inspect', 'backup', 'restore'}:
        raise ValueError('unsupported_action')
    for key in ('repository_id', 'snapshot_id'):
        if inputs[key] is not None and not DIGEST.fullmatch(inputs[key]):
            raise ValueError('repository_selection_invalid')
    location = inputs['location']
    repository_uri = 'rclone:opsctl:' + location['bucket'] + '/' + location['prefix']
    if inputs.get('interrupted_operation_id') is None:
        prepare_material(directory, location)
    selected = (inputs['native'] if action == 'backup' else inputs['target'] if action == 'restore'
                else inputs.get('interrupted_volume'))
    if selected is not None and not NAME.fullmatch(selected['name']):
        raise ValueError('native_name_invalid')
    tool_name = 'opsctl-backup-' + operation
    extractor_name = tool_name + '-rclone'
    owned = []
    locks = []
    try:
        lock_names = ['repository:' + repository_uri]
        if selected is not None:
            lock_names.append('volume:' + selected['name'])
        for name in sorted(lock_names):
            key = hashlib.sha256(name.encode()).hexdigest()
            descriptor = os.open('/run/lock/opsctl-backup-' + key,
                                 os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            lock = os.fdopen(descriptor, 'w')
            locks.append(lock)
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if inputs.get('interrupted_operation_id') is not None:
            previous = inputs['interrupted_operation_id']
            if action != 'inspect' or not re.fullmatch(r'[a-f0-9-]{36}', previous):
                raise ValueError('interrupted_selection_invalid')
            close_idle_tool(previous, repository_uri)
        if selected is not None:
            require_zero_users(selected['name'])
            if action == 'backup':
                native_volume(selected)
            elif action == 'restore':
                existing = docker('volume', 'ls', '-q', '--filter', 'name=^' + selected['name'] + '$')
                if existing.stdout.strip():
                    raise ValueError('restore_destination_already_exists')
                labels = selected['labels']
                if not isinstance(labels, dict) or not labels:
                    raise ValueError('restore_labels_required')
                arguments = [part for key, value in sorted(labels.items()) for part in ('--label', key + '=' + value)]
                docker('volume', 'create', '--driver', 'local', *arguments, selected['name'])
                native = native_volume(selected)
                result['target'] = {**selected, 'created_at': native['CreatedAt']}
                require_zero_users(selected['name'])
            else:
                found = docker('volume', 'ls', '-q', '--filter', 'name=^' + selected['name'] + '$')
                if found.stdout.strip():
                    native = native_volume(selected)
                    result['interrupted_volume'] = {**selected, 'created_at': native['CreatedAt']}
                elif selected['created_at'] is not None:
                    raise ValueError('interrupted_source_missing')
        if inputs.get('interrupted_operation_id') is not None:
            result['interruption_checked'] = True
            prepare_material(directory, location)
        for image in (RESTIC, RCLONE):
            if docker('image', 'inspect', image, check=False).returncode:
                docker('pull', image)
        for name in (tool_name, extractor_name):
            if docker('container', 'inspect', name, check=False).returncode == 0:
                raise ValueError('tool_identity_already_exists')
        extraction = docker('create', '--name', extractor_name, '--network', 'none', RCLONE).stdout.decode().strip()
        owned.append(extraction)
        docker('cp', extraction + ':/usr/local/bin/rclone', str(directory / 'rclone'))
        os.chmod(directory / 'rclone', 0o500)
        mounts = ['--mount', 'type=bind,src=' + str(directory) + ',dst=/run/private,readonly',
                  '--mount', 'type=bind,src=' + str(directory / 'rclone') + ',dst=/usr/bin/rclone,readonly']
        if selected is not None and action in {'backup', 'restore'}:
            mounts += ['--mount', 'type=volume,src=' + selected['name'] + ',dst='
                       + ('/data,readonly' if action == 'backup' else '/restore')]
        tool = docker('create', '--name', tool_name, '--label', 'io.opsctl.backup.operation=' + operation,
            '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--cap-add', 'DAC_OVERRIDE', '--cap-add', 'CHOWN', '--cap-add', 'FOWNER', '--cap-add', 'FSETID',
            '--tmpfs', '/tmp:rw,nosuid,nodev', '--env-file', str(directory / 'backup.env'),
            '-e', 'RESTIC_REPOSITORY=' + repository_uri, '-e', 'RESTIC_CACHE_DIR=/tmp/cache',
            *mounts, '--entrypoint', '/bin/sh', RESTIC, '-c', 'exec sleep 86400').stdout.decode().strip()
        owned.append(tool)
        docker('start', tool)
        if selected is not None and action in {'backup', 'restore'}:
            native_volume(result['target'] if action == 'restore' else selected)
            require_zero_users(selected['name'], own=tool)

        def restic(*argv):
            return docker('exec', tool, 'restic', '-o', 'rclone.program=/usr/bin/rclone',
                '-o', 'rclone.args=serve restic --stdio --config /dev/null', *argv).stdout

        version = restic('version').decode().split()
        if len(version) < 2 or version[0] != 'restic':
            raise ValueError('tool_version_unavailable')
        result['restic_version'] = version[1]
        if action == 'init':
            restic('init')
        configuration = json.loads(restic('cat', 'config'))
        repository_id = configuration['id']
        if (not DIGEST.fullmatch(repository_id)
                or inputs['repository_id'] is not None and repository_id != inputs['repository_id']):
            raise ValueError('repository_identity_changed')
        result['repository_id'] = repository_id
        snapshot_id = inputs['snapshot_id']
        if action == 'backup':
            output = restic('backup', '--json', '--tag', 'opsctl:' + operation, '/data')
            summaries = [item for line in output.splitlines() if line
                         for item in (json.loads(line),) if item.get('message_type') == 'summary']
            if len(summaries) != 1 or not DIGEST.fullmatch(summaries[0].get('snapshot_id', '')):
                raise ValueError('backup_snapshot_unavailable')
            snapshot_id = summaries[0]['snapshot_id']
        inventory = json.loads(restic('snapshots', '--json', '--latest', '100', '--group-by', ''))
        result['snapshots'] = [snapshot_record(item, repository_id) for item in inventory][:100]
        if snapshot_id is not None:
            exact = json.loads(restic('snapshots', '--json', snapshot_id))
            if len(exact) != 1 or exact[0]['id'] != snapshot_id or exact[0].get('paths') != ['/data']:
                raise ValueError('snapshot_selection_changed')
            snapshot = snapshot_record(exact[0], repository_id)
            if action == 'restore':
                restic('restore', snapshot_id + ':/data', '--target', '/restore', '--verify')
            # Only the selected snapshot's reachable bytes are read. No pack parser or history scan.
            digest = docker('exec', tool, '/bin/sh', '-c',
                'set -o pipefail; restic -o rclone.program=/usr/bin/rclone '
                '-o "rclone.args=serve restic --stdio --config /dev/null" '
                'dump ' + snapshot_id + ':/data / | sha256sum').stdout.decode().split()[0]
            if not DIGEST.fullmatch(digest):
                raise ValueError('selected_data_verification_incomplete')
            snapshot.update(ready=True, verified_at=now(), archive_sha256=digest)
            result.update(snapshot=snapshot, verified=True)
            result['recovery'] = recovery_kit(location, snapshot, result['restic_version'])
        if selected is not None and action in {'backup', 'restore'}:
            native_volume(result['target'] if action == 'restore' else selected)
            require_zero_users(selected['name'], own=tool)
        result['source_detached'] = action == 'backup'
        result['interruption_checked'] = inputs.get('interrupted_operation_id') is not None
        result['outcome'] = 'succeeded'
    finally:
        for identity in reversed(owned):
            docker('rm', '-f', identity, check=False)
        for lock in reversed(locks):
            lock.close()


def main():
    directory = Path(sys.argv[1]).resolve(strict=True)
    inputs = json.loads((directory / 'intent.json').read_bytes())
    result = {'action': inputs['action'], 'operation_id': inputs['operation_id'],
              'repository_id': None, 'restic_version': None, 'observed_at': now(),
              'outcome': 'unknown', 'source_detached': False, 'verified': False,
              'snapshot': None, 'snapshots': [], 'target': None,
              'interruption_checked': False, 'interrupted_volume': None, 'recovery': None}
    try:
        execute(inputs, directory, result)
    except (ValueError, KeyError, TypeError, OSError, subprocess.SubprocessError):
        result['outcome'] = 'failed'
    result['observed_at'] = now()
    print(json.dumps({'volume_backup': result}, separators=(',', ':')))
    return 0 if result['outcome'] == 'succeeded' else 1


if __name__ == '__main__':
    sys.exit(main())
