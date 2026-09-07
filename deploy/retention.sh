#!/usr/bin/env bash
# Invoke on the hosted machine only after deploying retention.py beside this script.
set -euo pipefail
umask 077
readonly APP_DIR=/opt/samlscope
readonly DATA_DIR=/srv/samlscope/data
readonly BACKUP_DIR=/srv/samlscope/backups
if (( $# > 1 )) || [[ "${1:-}" != "" && "${1:-}" != "--preview" && "${1:-}" != "--apply" ]]; then
  echo "Usage: retention.sh [--preview|--apply]" >&2
  exit 2
fi
if [[ "${1:-}" != "--apply" ]]; then
  python3 "$APP_DIR/retention.py" --data-dir "$DATA_DIR"
  exit
fi
exec 9>"$APP_DIR/deploy.lock"
flock -n 9 || { echo "Deployment or maintenance is running." >&2; exit 3; }
compose=(docker compose --env-file "$APP_DIR/.env" -f "$APP_DIR/compose.yaml")
"${compose[@]}" stop samlscope
# Fail closed: a failed backup or partial cleanup must not restart the service.
mkdir -p "$BACKUP_DIR"
backup="$(mktemp "$BACKUP_DIR/preretention-XXXXXXXX.tar.gz")"
tar --xattrs --acls -C "$DATA_DIR" -czf "$backup" .
sha256sum "$backup" > "$backup.sha256"
python3 "$APP_DIR/retention.py" --data-dir "$DATA_DIR" --apply --service-stopped
"${compose[@]}" start samlscope
echo "Retention completed; backup: $backup"
