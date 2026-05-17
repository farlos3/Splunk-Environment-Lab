#!/usr/bin/env bash
# Nuke the Splunk lab and restart with a fresh container.
# Mirrors reset.ps1.
#
# What this DOES wipe (default):
#   - The container itself
#   - splunk-var volume (indexed system data, _internal logs, trial state)
#   - splunk-etc-users volume (saved searches, dashboards)
#
# What this DOES NOT touch (default):
#   - splunk-botsv1 / splunk-botsv2 / splunk-botsv3 volumes (the BOTS
#     indexes — kept so we don't re-copy from bots-data/ on every reset)
#   - bots-data/ on the host
#
# Pass --full to also wipe the BOTS volumes. The next setup.sh run will
# then re-populate the requested datasets from bots-data/<vN>/.
#
# Usage:
#   ./docker/reset.sh           # fast reset, keep BOTS volumes
#   ./docker/reset.sh --full    # nuke EVERYTHING, requires re-populate
#   ./docker/reset.sh --force   # skip confirmation

set -euo pipefail

FULL=0
FORCE=0
for arg in "$@"; do
    case "$arg" in
        --full) FULL=1 ;;
        --force) FORCE=1 ;;
        *) echo "Unknown argument: $arg"; exit 1 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"

BOTS_VOLUMES=(splunklab_splunk-botsv1 splunklab_splunk-botsv2 splunklab_splunk-botsv3)
STATE_VOLUMES=(splunklab_splunk-var splunklab_splunk-etc-users)

echo
echo "Splunk Lab — Reset"
echo "----------------------------------------"
echo "Compose file : $COMPOSE_FILE"
if [ "$FULL" -eq 1 ]; then
    echo "Mode         : FULL (wipes BOTS volumes too — next setup re-populates)"
else
    echo "Mode         : fast  (keeps BOTS volumes — re-uses indexed data)"
fi
echo

if [ "$FORCE" -ne 1 ]; then
    read -rp "Continue? [y/N] " answer
    case "$answer" in
        [Yy]*) ;;
        *) echo "Aborted."; exit 0 ;;
    esac
fi

echo "==> Stopping container (without --volumes so we control what's wiped)"
docker compose -f "$COMPOSE_FILE" down --remove-orphans

if [ "$FULL" -eq 1 ]; then
    echo "==> Removing ALL named volumes (including BOTS data)"
    docker volume rm "${STATE_VOLUMES[@]}" "${BOTS_VOLUMES[@]}" 2>/dev/null || true
else
    echo "==> Removing only state volumes (keeping BOTS data)"
    docker volume rm "${STATE_VOLUMES[@]}" 2>/dev/null || true
fi

echo "==> Starting fresh Splunk container"
docker compose -f "$COMPOSE_FILE" up -d

echo
echo "Splunk is booting (60-120 seconds)."
echo "  Web UI   : http://localhost:8000"
echo "  Username : admin"
echo "  Password : p@ssw0rd"
echo
if [ "$FULL" -eq 1 ]; then
    echo "BOTS volumes were wiped — run ./setup.sh [--v1|--v2|--v3|--all] to re-populate."
else
    echo "Tail boot log: docker logs -f splunk-lab"
fi
