#!/usr/bin/env python3
"""Refuse incomplete or conflicting native lego account storage without repair."""

import json
import os
import re
import stat
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

from certificate_facts import read_file


def private_directory(path):
    """Require an existing canonical root-owned private directory."""
    if not path.is_absolute() or path.resolve() != path:
        raise ValueError
    metadata = path.lstat()
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o700):
        raise ValueError


def entries(path, maximum):
    """Bound inspection to the selected native namespace or account."""
    names = set()
    with os.scandir(path) as children:
        for child in children:
            names.add(child.name)
            if len(names) > maximum:
                raise ValueError
    return names


def validate(root, server, email, account_id):
    """Allow initial creation or exact complete native registration reuse."""
    root = Path(root)
    private_directory(root)
    directory = urlsplit(server)
    if (directory.scheme != "https" or not directory.netloc
            or directory.username is not None or directory.password is not None
            or directory.query or directory.fragment
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", account_id) is None):
        raise ValueError
    host = unquote(directory.netloc, errors="strict")
    namespace = host.translate(str.maketrans({":": "_", "/": "_", "\\": "_"}))
    if namespace in (".", "..") or not namespace:
        raise ValueError
    ca = root / namespace
    try:
        ca.lstat()
    except FileNotFoundError:
        return
    private_directory(ca)
    identities = entries(ca, 1)
    if not identities:
        return
    if identities != {account_id}:
        raise ValueError
    account = ca / account_id
    private_directory(account)
    key_name = account_id + ".key"
    if entries(account, 2) != {"account.json", key_name}:
        raise ValueError
    for name in ("account.json", key_name):
        if (account / name).lstat().st_nlink != 1:
            raise ValueError
    saved = json.loads(read_file(account / "account.json", 65536, private=True))
    if (not isinstance(saved, dict) or saved.get("server") != server
            or saved.get("email") != email or saved.get("id") != account_id
            or not isinstance(saved.get("keyType"), str) or not saved["keyType"]):
        raise ValueError
    registration = saved.get("registration")
    if (not isinstance(registration, dict) or registration.get("status") != "valid"
            or not isinstance(registration.get("accountURL"), str)
            or not registration["accountURL"].strip()
            or not read_file(account / key_name, 65536, private=True).strip()):
        raise ValueError


if __name__ == "__main__":
    try:
        if len(sys.argv) != 5:
            raise ValueError
        validate(*sys.argv[1:])
    except Exception:
        sys.stderr.write("ACME account storage is unavailable.\n")
        sys.exit(1)
