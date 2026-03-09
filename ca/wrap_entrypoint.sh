#!/bin/bash

set -e

export STEPPATH=$(step path)

echo "[!] Before original entrypoint"
export PGPASSWORD=$POSTGRES_PASSWORD
until pg_isready -h "$PG_HOST" -p "$PG_PORT" -U "$POSTGRES_USER" -d "stepca"; do
  echo "[!] Waiting for postgres to come up..."
  sleep 1
done

# if the CA was not bootstrapped at all
if [ ! -f "${STEPPATH}/config/ca.json" ]; then
  # we must perform original init without remote management
  # to avoid the init procedure writing to the default badgerv2 database
  # we will re-enable the remote management soon after the original init
  export DOCKER_STEPCA_INIT_REMOTE_MANAGEMENT=false
  /bin/bash /entrypoint.sh

  echo "[!] Patch config on init"
  python -u /extra/patch_cfg_init.py
fi

echo "[!] Patch config on run"
python -u /extra/patch_cfg_run.py

DB_URL="postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@${PG_HOST}:${PG_PORT}/stepca"

if [ -f "${STEPPATH}/db/MANIFEST" ]; then
  echo "[!] Performing Badger database migration"
  echo "[!] Setting initial_sync_state to in_progress"
  QUERY=$(cat <<EOF
UPDATE tinypki_indexer_meta SET mvalue = '{"state": "in_progress"}' WHERE mkey = 'initial_sync_state';
EOF
)
  psql "${DB_URL}" -c "$QUERY"
  badger-migration -v2 -dir "${STEPPATH}/db" -type=postgresql -database "${DB_URL}"

  echo "[!] Deleting Badger database files"
  rm -rf "${STEPPATH}/db/"
fi

echo "[!] Setting initial_sync_state to synced"
QUERY=$(cat <<EOF
UPDATE tinypki_indexer_meta SET mvalue = '{"state": "synced"}' WHERE mkey = 'initial_sync_state';
EOF
)
psql "${DB_URL}" -c "$QUERY"

echo "[!] Launching Step CA"
exec "${@}"
