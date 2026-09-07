# Hosted operations preparation

Status: preparation only. Production provider and operator setup are pending.
Do not interpret deployment manifests or a healthy process as launch acceptance.

## Implementation inventory

| Capability | Existing behavior | Remaining launch work |
|---|---|---|
| Deployment | `deploy/deploy.sh` pulls a pinned image, stops the service, archives the data directory and checks health | Exercise on the chosen host; record image and backup provenance |
| Rollback | Script restores the previous image environment after failed health checks | Data is not restored; establish schema compatibility or restore the matching snapshot |
| Publication | Hosted publish route and sanitized public artifacts | Exercise anonymous view, owner authorization, CSRF and scrubbing with a disposable Run |
| Deletion | Plan deletion now also removes persisted results, Plan/Run metadata and Plan keys before deleting database rows | Hosted owner/CSRF/revocation checks pass; concurrent in-flight writer acceptance remains outstanding |
| Retention | Offline preview/apply utility and daily systemd timer templates are available | Operator installation, backup rotation and production rehearsal pending |
| Unpublication | Capacity rejection can remove publication internally | No owner-facing dedicated unpublish route established by this audit |

The specification's retention and deletion promises must not be presented as
operationally enforced until the remaining behavior is implemented and tested.

## Consistent backup

Use the existing deployment lock to exclude simultaneous deployment or maintenance.
Stop the application and confirm that no other process writes its data directory.
Archive the entire `/srv/samlscope/data` tree, including SQLite sidecars, keys,
metadata, Transcripts and result artifacts. Copying only the database while the
application runs is not a backup of the complete evidence set.

The deployment script already makes this stopped-service archive before upgrades.
Record its SHA-256, timestamp, Suite image reference/digest and configuration
version in a private backup inventory. Restrict archive access and encrypt off-host
copies: redacted evidence and generated private keys remain sensitive. Keep
backup access separate from public artifact access. Define backup retention with
the operator before launch; no automated rotation is currently claimed.

## Restore rehearsal

1. Select a trusted backup and verify its recorded checksum. Keep the source
   archive unchanged and inspect its file listing before extraction.
2. Extract into a new private directory, never over the live data directory.
   Preserve ownership appropriate to the container. Include any WAL sidecar;
   do not mix files from different snapshots.
3. With the restored copy offline, run SQLite `PRAGMA integrity_check` and
   `PRAGMA foreign_key_check` against the selected database (`samlscope.db`, or
   `samlier.db` for legacy installations). Require `ok` and no foreign-key rows.
4. Start the exact backed-up image against the restored copy, isolated from
   public ingress and test targets. Prevent resumed actions reaching real targets.
5. Confirm health, Plan/Run availability, evidence file references, private/public
   access boundaries, and JSON/HTML consistency. Compare selected artifact hashes
   with the backup inventory. Do not expose management secrets in the record.
6. Record success or failure, recovery duration, missing artifacts and the image
   used. A successful SQL integrity check alone is insufficient.

Production recovery requires a maintenance window: stop writes, preserve the
failed data tree for investigation, select the compatible image/snapshot pair,
restore and run acceptance before enabling ingress. The current deploy script's
automatic image rollback does not perform these data-recovery steps.

## Deletion and retention acceptance

Use disposable fixtures to test owner access and denied anonymous/cross-owner
access. Inventory the Run's database rows, Transcript paths, generated results,
cached metadata, publication and access grants before deletion. Afterwards verify
all required removals on disk as well as HTTP denial; a hidden report is not proof
of file erasure. Plan deletion must not be described as a dedicated Run deletion.

Define how expired private Runs, published Transcripts and deletion requests are
processed, retried after interruption and reconciled with backup retention.
Restoring a backup must reapply deletions made after its snapshot before public
ingress resumes. Select an operator contact and publish the actual retention
policy only after these behaviors are accepted.

## Launch gate

Require signed release verification, the reference acceptance matrix with honest
unresolved results, a successful restore rehearsal, complete deletion and retention
acceptance, publication/access checks, TLS and origin separation, and the operator's
provider/contact/cost decisions. Track evidence in [release readiness](13-release-readiness.md).


## Offline retention tooling

`deploy/retention.py` previews expired private Runs and published Transcript entries.
Private Run age is measured from Run creation; published Transcript age is measured
per entry from its recording timestamp. The exact boundary expires the item.
Published results, recent Transcript entries and reusable Plans/Plan keys remain.
Run deletion also removes access grants and case/outbox rows through foreign keys;
usage accounting is recomputed without clearing rejection flags.

```bash
python3 deploy/retention.py --data-dir /path/to/stopped-copy
python3 -m unittest discover -s deploy -p 'test_*.py' -v
```

Application requires both `--apply` and `--service-stopped`; use these only for a
stopped service or an isolated offline copy. All deletion paths are validated
before mutation, and symlinks or unexpected Transcript references abort execution.
File deletion precedes SQL deletion so a failed attempt retains the Run/entry
identifiers for retry. On failure, keep the service stopped, investigate and retry
or restore the pre-maintenance snapshot; do not serve partially removed evidence.

On the eventual Linux host, install `retention.py` and `retention.sh` under
`/opt/samlscope`. The shell wrapper uses the same deployment lock, stops the service,
backs up the complete data tree and restarts only after successful cleanup.
Install the supplied service/timer units only after operator rehearsal; the timer
runs daily at 04:00 in the host timezone and catches up after downtime. These files
have not been installed on a production machine. Routine maintenance briefly
interrupts service and must be included in the operating policy.

Tests cover expiry boundaries, preview immutability, preservation of published
results and recent entries, accounting, repeated application, and unsafe paths.
A copy of the real Keycloak fixture was also expired using a simulated future
clock; no original acceptance data was deleted. The Linux wrapper and timer have
only undergone syntax/configuration review on this macOS workstation.

Backups intentionally still contain expired data. Define backup rotation and
post-restore deletion reconciliation before enabling the timer in production;
this utility does not silently select a backup retention policy.
