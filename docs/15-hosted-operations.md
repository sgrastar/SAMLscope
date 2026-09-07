# Hosted operations preparation

Status: preparation only. Production provider and operator setup are pending.
Do not interpret deployment manifests or a healthy process as launch acceptance.

## Implementation inventory

| Capability | Existing behavior | Remaining launch work |
|---|---|---|
| Deployment | `deploy/deploy.sh` pulls a pinned image, stops the service, archives the data directory and checks health | Exercise on the chosen host; record image and backup provenance |
| Rollback | Script restores the previous image environment after failed health checks | Data is not restored; establish schema compatibility or restore the matching snapshot |
| Publication | Hosted publish route and sanitized public artifacts | Exercise anonymous view, owner authorization, CSRF and scrubbing with a disposable Run |
| Deletion | Plan deletion removes Transcript trees and cascaded database rows | Results and cached metadata are separate files; complete erasure needs verification and implementation |
| Retention | Design specifies retention periods | No scheduled retention implementation established by this audit |
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
