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
#   - splunk-botsv1 volume (the 9 GB BOTSv1 index — kept so we don't
#     re-copy from bots-data/ for 5 min on every reset)
#   - bots-data/ on the host
#
# Pass --full to also wipe splunk-botsv1. The next setup.sh run will
# then re-populate it from bots-data/ (~5 min copy).
#
# Usage:
#   ./docker/reset.sh           # fast reset, keep BOTSv1 volume
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

echo
echo "Splunk Lab — Reset"
echo "----------------------------------------"
echo "Compose file : $COMPOSE_FILE"
if [ "$FULL" -eq 1 ]; then
    echo "Mode         : FULL (wipes splunk-botsv1 too — next setup re-populates)"
else
    echo "Mode         : fast  (keeps splunk-botsv1 — re-uses ~9 GB BOTSv1 data)"
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
    echo "==> Removing ALL named volumes (including splunk-botsv1)"
    docker volume rm splunklab_splunk-var splunklab_splunk-etc-users splunklab_splunk-botsv1 2>/dev/null || true
else
    echo "==> Removing only state volumes (keeping splunk-botsv1)"
    docker volume rm splunklab_splunk-var splunklab_splunk-etc-users 2>/dev/null || true
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
    echo "BOTSv1 volume was wiped — run ./setup.sh to re-populate (~5 min)."
else
    echo "Tail boot log: docker logs -f splunk-lab"
fi
