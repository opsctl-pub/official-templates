# Offline encrypted file copy

`backup` is plain operation-bound intent: action (`init`, `inspect`, `backup`,
`restore`), typed storage location/full repository identity, optional full snapshot, and exact native
source or fresh target. Private S3 credentials/password arrive as files, never
public variables. The procedure alone renders tool environment/recovery instructions.
Restic0.19.1 and rclone1.70.3 are digest-pinned in the readable
script. rclone S3 `no_check_bucket` skips bucket creation, including races after
preparation. TLS verification remains enabled; an optional user CA is delivered
privately with the invocation. Storage permissions require read/list/write/lock.

Backup requires detached, ordinary local/no-options storage and zero native
containers (including stopped users). The original is mounted read-only until
selected-snapshot `dump` verification finishes. This is offline file consistency,
not application/DB consistency. Privileged host actors are outside controlled-host
exclusion. Exact name/time plus managed labels or Compose birth marker are checked;
markers are not authority and cannot resist deliberate privileged duplication.
The first subset also requires no unresolved native entry on the selected Server;
current workload mount owners must show the source detached. Unknown mount coverage
refuses rather than borrowing data-deletion eligibility.

Restore creates only a previously absent labeled target. `restore --verify`
must finish before the API can publish availability. Partial creation/data is
reported and retained quarantined on failure, never automatically deleted or
attached. Interruption is not completion. No automatic unlock, forget, prune,
bucket creation, attach, cutover or app-health claim exists.

An explicit inspect can reconcile one exact interrupted invocation only after
backend-recorded native/writer closure. The procedure obtains the original
repository/volume lock, refuses active tool processes, removes only the exact
owned idle tool, and observes identity/zero users afresh. It never unlocks a
restic repository. An unverified restored backing remains quarantined even after
inspection; it may be removed through the ordinary data-loss owner, not attached.

`volume_backup` reports operation/action, repository identity, observed time,
actual tool version, outcome, native exclusion, selected snapshot verification,
bounded recorded snapshot inventory and nullable target creation facts. Snapshot
identity is content-addressed, not a WORM/availability promise. Only selected
reachable bytes are verified, not all historical packs. A portable recovery kit
plus independently retained password/storage credentials can use native-S3 restic
without the OpsCtl database. Losing that password loses recovery.

Repository inventory is not proof of source completeness: restic can retain an
incomplete snapshot after nonzero backup exit. The API therefore publishes restore
readiness only for snapshots whose successful backup and verification were recorded
in durable destination metadata. Inspecting reachable bytes cannot upgrade an
unknown/incomplete snapshot into a source-complete backup.
