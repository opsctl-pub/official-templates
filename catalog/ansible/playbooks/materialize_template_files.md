# Materialize Template Files

`materialize_template_files.yml` delivers a frozen file set to a fresh private
directory on each selected target. It does not execute the entry point, install
packages, provision a Server or invoke a Hook. It gathers no facts and uses no
privilege escalation by default. The caller supplies the authorized inventory and
target user; controller observations explicitly disable escalation.

## Inputs

| Input | Contract |
| --- | --- |
| `template_source_directory` | Absolute, canonical controller-side staged directory. It and every ancestor must be actual directories, not symlinks. No repeated/trailing separator (except `/`), dot/dot-dot segment, backslash or control character. |
| `template_supplied_files` | Ordered list of 1..32 records containing exactly `path`, `source`, `mode`, `size_bytes`, `sha256`. |
| `template_entrypoint` | Exact relative `path` member of that list; not an interpreter or command. |

Each destination is a canonical relative POSIX path of 1..256 UTF-8 bytes. Absolute
paths, empty/dot/dot-dot segments, backslashes, colons, ASCII control characters and
DEL refuse. Paths and flat staged keys are case-sensitive and unique; no file can
also be another file's ancestor. `source` matches `source-[0-9]{2}` exactly.
`mode` is exactly one of the strings `0600`, `0644`, `0700`, `0755`, preserved
from authenticated regular-source custody without normalization. `size_bytes` is a strict integer (not a
boolean), 0..262144 per file, at most 1048576 total. `sha256` is exactly 64 lowercase
hexadecimal characters. Record order is retained.

The caller must freeze staged regular files on a read-only mount for the entire
invocation. URLs, mutable Git references and payload text in variables are not
inputs. Controller no-follow metadata and SHA-256 must match the manifest before
any target workspace is allocated. No file contents are slurped or logged.

## Delivery And Lifetime

Native `tempfile` allocates a fresh target directory at mode `0700`. Only required
parents are created, also `0700`; original bytes are copied with the supplied modes.
This engine-agnostic procedure does not check Bash executability; the content and
admission owner requires a Bash entry point already at `0700` or `0755`.
There is no caller-selected target workspace and no overwrite of an old invocation.
Copying is not Jinja rendering: binary data, template delimiters and dollar
expressions remain literal. File-detail tasks use `no_log`; copy diffs are disabled.
Delivered regular-file type, mode, size and SHA-256 are checked before success.

The target user needs writable native temporary storage and the ordinary Ansible
module prerequisites. Source and workspace must remain under their owners' exclusive
custody during delivery; separate metadata checks are not atomic protection against
a concurrent same-user filesystem writer. The later isolated execution owner must
provide that custody. Filesystem-specific constraints can still cause delivery to
fail, even when a path meets the portable input limits.

A successful workspace is retained for the later execution consumer, which owns
its eventual removal. Success grants no permission to execute its contents. Any
language needs a declared interpreter and prerequisites from that later owner;
this procedure provides neither a Python engine nor automatic package installation.

## Progress And Result

The existing `OPERATION_STEP` marker uses `name: template:files`, with `running`
and then `completed` or `failed`. Exactly one final `TEMPLATE_OUTPUT_JSON` contains
`template_file_delivery` with these plain fields:

| Field | Meaning |
| --- | --- |
| `outcome` | `delivered` or `refused`. |
| `reason` | `delivered`, `invalid_inputs`, `source_unavailable`, `source_mismatch`, `delivery_failed`, `verification_failed` or `cleanup_failed`. |
| `original_reason` | Null on success; original failure reason on refusal, including when cleanup subsequently fails. |
| `cleanup` | `not_allocated`, `not_required`, `removed` or `failed`. `removed` requires observed absence. |
| `workspace` | Null unless an invocation-owned directory has been verified and remains. A path on cleanup failure is a retained liability, not successful delivery. |
| `entrypoint` | Validated relative entry point, or null when input validation did not complete. |
| `files` | Verified ordered `{path, mode, size_bytes, sha256}` records on success; empty on refusal. Never staged keys or file contents. |

Missing, symlink or incompatible staged paths yield `source_unavailable`; size or
checksum differences yield `source_mismatch`. Invalid inputs and source refusals
create no target workspace. Allocation, parent creation and copying failures yield
`delivery_failed`; delivered-file checks yield `verification_failed`.

On failure, cleanup observes the native allocation and compares directory device,
inode and owner before removing only that invocation's workspace. Missing identity
or a replaced directory refuses deletion. Removal must be followed by observed
absence. Failed or uncertain cleanup yields `cleanup_failed`, preserves
`original_reason` and reports only a qualified retained workspace; otherwise the
path is null. A refused delivery fails the play after publishing its result.
Unreachable targets or an interrupted controller can prevent both cleanup and a
terminal result; callers must retain that uncertainty rather than assume removal.
Cleanup never claims to undo user-data effects, and this procedure never runs user
code. No scheduler, automatic retry or workspace-lifetime framework is supplied.

## Current Integration Boundary

This standalone procedure is a foundation, not a registered public run command,
file editor, source-custody API or Hook/Profile dispatcher. Acceptance and isolated
execution placement remain separate requirements before live use.
