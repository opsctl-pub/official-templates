# Synchronize managed SSH access

## Inputs

`ssh_access_sync.yml` uses the selected Server inventory and privilege escalation.
`ssh_users` defaults to an empty list; entries contain `username`, `state` and,
for present keys, `public_key`. `sshd_config_path` defaults to `/etc/ssh/sshd_config`
and `opsctl_authorized_keys_file` to `authorized_keys_opsctl`. `simulate` defaults
to false. These are public keys, never private-key input or output.

## Behavior

Retain the normal authorized_keys path and add the OpsCtl-managed file to sshd.
Validate and reload sshd only when that setting changes. Combine requested keys
by username, create present users/home directories, and write complete managed
files with 0700 directories and 0600 files. For absent users, remove only their
managed key file, not the Linux user or unmanaged keys. Missing passwd/group
facts prevent the corresponding file operation. Simulation ends before effects.
Partial failure does not undo earlier user, file or sshd changes.

## Results

There is no `TEMPLATE_OUTPUT_JSON` result. Progress includes present/absent user
counts, not proof that a particular client can authenticate. Failure propagates
the existing diagnostic; completion is not ongoing SSH reachability.

## Progress

Existing steps are `ssh-access:start`, `ssh-access:sshd-config`, `ssh-access:users`,
`ssh-access:complete` and `ssh-access:failure`.
