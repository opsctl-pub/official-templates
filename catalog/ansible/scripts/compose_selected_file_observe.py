#!/usr/bin/env python3
"""Observe selected regular files through confined, revalidated descriptors."""

from contextlib import ExitStack
import errno
import hashlib
import json
import os
from pathlib import PurePosixPath
import stat
import sys
from unicodedata import category


FILE_LIMIT = 262144
TOTAL_LIMIT = 1048576


def canonical_path(value, absolute=False):
    """Require original canonical spelling without normalizing a selection."""
    if not isinstance(value, str) or not value or value == '.':
        return False
    try:
        length = len(value.encode('utf-8'))
    except UnicodeEncodeError:
        return False
    path = PurePosixPath(value)
    return (length <= (4096 if absolute else 256)
            and path.is_absolute() == absolute and path.as_posix() == value
            and not value.startswith('//') and '..' not in path.parts
            and '\\' not in value and not any(category(char) == 'Cc' for char in value))


def validate_request(workspace, paths):
    """Validate complete membership before any filesystem access."""
    if not canonical_path(workspace, absolute=True) or workspace == '/':
        raise ValueError('invalid_request')
    if (type(paths) is not list or len(paths) > 32
            or not all(canonical_path(path) for path in paths)
            or len(set(paths)) != len(paths)):
        raise ValueError('invalid_request')


def metadata(value):
    """Compare identity and mutation facts, excluding read-driven access time."""
    return (value.st_dev, value.st_ino, value.st_mode, value.st_size,
            value.st_uid, value.st_gid, value.st_nlink,
            value.st_mtime_ns, value.st_ctime_ns)


def unknown(path, reason):
    """Retain membership without speculative size, mode or digest."""
    return {'path': path, 'presence': 'unknown', 'size_bytes': None,
            'mode': None, 'sha256': None, 'reason': reason}


def error_reason(error):
    """Project OS failures into the documented vocabulary only."""
    if error.errno in (errno.EACCES, errno.EPERM):
        return 'permission_denied'
    if error.errno in (errno.ELOOP, errno.ENOTDIR):
        return 'unsafe_path'
    return 'read_failed'


class ChangedDuringCollection(Exception):
    """A held object or directory entry no longer matches its read identity."""


class DirectoryChain:
    """Hold every ancestor and revalidate its no-follow directory entry."""

    def __init__(self, stack):
        self.stack = stack
        self.held = []
        self.edges = []
        self.fd = self.hold(os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC))

    def hold(self, descriptor):
        """Close a descriptor even when later observation refuses."""
        self.stack.callback(os.close, descriptor)
        self.held.append((descriptor, os.fstat(descriptor)))
        return descriptor

    def descend(self, component):
        """Open one directory relative to its held parent without following links."""
        parent = self.fd
        descriptor = os.open(component, os.O_RDONLY | os.O_DIRECTORY
                             | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        self.fd = self.hold(descriptor)
        self.edges.append((parent, component, os.fstat(descriptor)))

    def verify(self):
        """Check held ancestors and final entries without resolving pathnames."""
        for descriptor, before in self.held:
            if metadata(os.fstat(descriptor)) != metadata(before):
                raise ChangedDuringCollection()
        for parent, component, before in self.edges:
            try:
                after = os.stat(component, dir_fd=parent, follow_symlinks=False)
            except OSError as error:
                raise ChangedDuringCollection() from error
            if metadata(after) != metadata(before):
                raise ChangedDuringCollection()


def absent(chain, component, path):
    """Qualify nonexistence only while the complete confined ancestry is stable."""
    chain.verify()
    try:
        os.stat(component, dir_fd=chain.fd, follow_symlinks=False)
    except FileNotFoundError:
        chain.verify()
        return {**unknown(path, 'missing'), 'presence': 'absent'}
    raise ChangedDuringCollection()


def observe_file(workspace, path, budget):
    """Hash bounded bytes on the opened descriptor and verify its final binding."""
    with ExitStack() as stack:
        chain = DirectoryChain(stack)
        for component in PurePosixPath(workspace).parts[1:]:
            chain.descend(component)
        parts = path.split('/')
        for component in parts[:-1]:
            try:
                chain.descend(component)
            except FileNotFoundError:
                return absent(chain, component, path)
        leaf = parts[-1]
        try:
            initial = os.stat(leaf, dir_fd=chain.fd, follow_symlinks=False)
        except FileNotFoundError:
            return absent(chain, leaf, path)
        if stat.S_ISLNK(initial.st_mode):
            return unknown(path, 'unsafe_path')
        if not stat.S_ISREG(initial.st_mode):
            return unknown(path, 'not_regular')
        try:
            descriptor = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                                 | os.O_CLOEXEC, dir_fd=chain.fd)
        except OSError as error:
            chain.verify()
            try:
                current = os.stat(leaf, dir_fd=chain.fd, follow_symlinks=False)
            except FileNotFoundError:
                raise ChangedDuringCollection() from error
            if metadata(current) != metadata(initial):
                raise ChangedDuringCollection() from error
            raise
        stack.callback(os.close, descriptor)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or metadata(before) != metadata(initial):
            raise ChangedDuringCollection()
        if before.st_size > FILE_LIMIT:
            return unknown(path, 'file_limit_exceeded')
        if before.st_size > TOTAL_LIMIT - budget['read']:
            budget['exceeded'] = True
            return unknown(path, 'total_limit_exceeded')
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                raise ChangedDuringCollection()
            budget['read'] += len(chunk)
            remaining -= len(chunk)
            digest.update(chunk)
        chain.verify()
        try:
            final = os.stat(leaf, dir_fd=chain.fd, follow_symlinks=False)
        except FileNotFoundError as error:
            raise ChangedDuringCollection() from error
        if metadata(os.fstat(descriptor)) != metadata(before) or metadata(final) != metadata(before):
            raise ChangedDuringCollection()
        return {'path': path, 'presence': 'present', 'size_bytes': before.st_size,
                'mode': format(stat.S_IMODE(before.st_mode), '04o'),
                'sha256': digest.hexdigest(), 'reason': None}


def collect(workspace, paths):
    """Keep every admitted selected path in order, including unavailable rows."""
    validate_request(workspace, paths)
    budget = {'read': 0, 'exceeded': False}
    rows = []
    for path in paths:
        if budget['exceeded']:
            rows.append(unknown(path, 'total_limit_exceeded'))
            continue
        try:
            rows.append(observe_file(workspace, path, budget))
        except ChangedDuringCollection:
            rows.append(unknown(path, 'changed_during_collection'))
        except OSError as error:
            rows.append(unknown(path, error_reason(error)))
    return {'selected_file_observations': rows,
            'selected_file_observation_complete': bool(rows)
            and all(row['presence'] != 'unknown' for row in rows)}


def main():
    """Emit only public metadata; never print paths or native exception text."""
    try:
        if len(sys.argv) != 3:
            raise ValueError('invalid_request')
        result = collect(sys.argv[1], json.loads(sys.argv[2]))
    except (ValueError, TypeError, UnicodeError):
        sys.stderr.write('Invalid selected-file observation request.\n')
        return 2
    sys.stdout.write(json.dumps(result, ensure_ascii=True) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
