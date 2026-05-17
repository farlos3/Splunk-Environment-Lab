#!/usr/bin/env bash
# One-shot bootstrap for the Splunk + BOTSv1 lab. Mirrors setup.ps1.
#
# Why it's not a simple "compose up": Splunk's validatedb refuses to use
# the BOTSv1 buckets when they live on a Docker Desktop Windows bind
# mount ("unusable filesystem" — gRPC-FUSE lacks the locking/mmap
# semantics Splunk wants). So we stage the dataset in ../bots-data/ on
# the host, then COPY it into a native Docker named volume that the
# Splunk container actually reads from.
#
# Steps (all idempotent):
#   1. download BOTSv1 .tgz into bots-data/  (resume-friendly)
#   2. validate + extract into bots-data/  (skipped if already done)
#   3. copy bots-data/ into the splunk-botsv1 named volume
#      (skipped if the volume already contains a default/ folder)
#   4. docker compose up -d
#   5. wait for the container to become healthy
#   6. verify the botsv1 app + index are visible to Splunk
#
# Usage:
#   ./setup.sh
#   ./setup.sh --url https://custom.example/botsv1.tgz
#   ./setup.sh --skip-download
#   ./setup.sh --force                # re-extract AND re-populate volume

set -euo pipefail

URL="https://s3.amazonaws.com/botsdataset/botsv1/splunk-pre-indexed/botsv1_data_set.tgz"
SKIP_DOWNLOAD=0
FORCE=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --url) URL="$2"; shift 2 ;;
        --skip-download) SKIP_DOWNLOAD=1; shift ;;
        --force) FORCE=1; shift ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$REPO_ROOT/docker/docker-compose.yml"
BOTS_DIR="$REPO_ROOT/bots-data"
CONTAINER="splunk-lab"
SPLUNK_PASS="p@ssw0rd"
# Named volume created by docker compose. Compose prefixes with the
# project name ("name: splunklab" at the top of docker-compose.yml).
VOLUME_NAME="splunklab_splunk-botsv1"
SPLUNK_UID=41812

# Practice challenges under challenges/splunk-bots/ are vendored into this
# repo. They originate from https://github.com/chan2git/splunk-bots — refer
# to that upstream for the original walkthroughs and any updates.

step() { echo; echo "==> $*"; }
info() { echo "    $*"; }

human() {
    awk "BEGIN {
        s = $1
        if (s >= 1073741824) printf \"%.2f GB\", s/1073741824
        else if (s >= 1048576) printf \"%.2f MB\", s/1048576
        else printf \"%d bytes\", s
    }"
}

file_size() {
    stat -c %s "$1" 2>/dev/null || stat -f %z "$1"
}

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------
step "Pre-flight checks"
for cmd in docker tar curl awk; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "ERROR: '$cmd' not found on PATH." >&2
        exit 1
    fi
done
info "docker, tar, curl, awk available"

# ---------------------------------------------------------------------------
# 1 + 2. Get the dataset extracted on host (staging area)
# ---------------------------------------------------------------------------
if [ -d "$BOTS_DIR/default" ] && [ "$FORCE" -ne 1 ]; then
    step "BOTSv1 already extracted on host — skipping download/extract"
    info "  found: $BOTS_DIR/default/"
    info "  (re-run with --force to overwrite)"
else
    if [ "$FORCE" -eq 1 ] && [ -d "$BOTS_DIR/default" ]; then
        step "Wiping existing bots-data/ contents (--force)"
        find "$BOTS_DIR" -mindepth 1 -maxdepth 1 \
            ! -name '.gitkeep' ! -name 'README.md' ! -name '*.tgz' \
            -exec rm -rf {} +
    fi

    # Find any local .tgz first
    TGZ="$(find "$BOTS_DIR" -maxdepth 1 -type f \( -name '*.tgz' -o -name '*.tar.gz' \) | head -n 1)"

    REMOTE_SIZE=""
    if [ "$SKIP_DOWNLOAD" -ne 1 ]; then
        step "Querying server for archive metadata"
        info "$URL"
        HEAD_OUT="$(curl -sIL --max-time 30 "$URL" || true)"
        http_code="$(echo "$HEAD_OUT" | awk '/^HTTP/ {code=$2} END {print code}')"
        REMOTE_SIZE="$(echo "$HEAD_OUT" | tr -d '\r' | awk 'tolower($1)=="content-length:" {print $2}' | tail -n 1)"

        if [[ ! "$http_code" =~ ^(200|301|302)$ ]]; then
            cat >&2 <<EOF

ERROR: HEAD request returned HTTP $http_code — URL is dead or unreachable.

Splunk has changed the BOTSv1 download URL several times. Please:
  1. Open https://github.com/splunk/botsv1
  2. Follow the current Download instructions
  3. Save the .tgz into:  $BOTS_DIR
  4. Re-run ./setup.sh
EOF
            exit 1
        fi
        if [ -n "$REMOTE_SIZE" ]; then
            info "remote size: $(human "$REMOTE_SIZE")"
        fi
    fi

    if [ -n "$TGZ" ]; then
        step "Found existing archive in bots-data/"
        info "path : $TGZ"
        LOCAL_SIZE="$(file_size "$TGZ")"
        info "size : $(human "$LOCAL_SIZE")"

        if [ "$SKIP_DOWNLOAD" -eq 1 ] || [ -z "$REMOTE_SIZE" ]; then
            info "skipping size comparison"
        elif [ "$LOCAL_SIZE" -eq "$REMOTE_SIZE" ]; then
            info "matches remote size — download not needed"
        elif [ "$LOCAL_SIZE" -lt "$REMOTE_SIZE" ]; then
            pct="$(awk "BEGIN {printf \"%.1f\", $LOCAL_SIZE*100/$REMOTE_SIZE}")"
            step "Resuming partial download (have ${pct}% of file)"
            curl -L --fail -C - --progress-bar -o "$TGZ" "$URL"
        else
            echo "WARNING: local file is LARGER than remote — likely corrupt." >&2
            echo "         Delete bots-data/$(basename "$TGZ") and re-run." >&2
            exit 1
        fi
    else
        if [ "$SKIP_DOWNLOAD" -eq 1 ]; then
            echo "ERROR: no .tgz found in bots-data/ and --skip-download set." >&2
            exit 1
        fi
        TGZ="$BOTS_DIR/botsv1_data_set.tgz"
        step "Downloading BOTSv1 (~6 GB)"
        info "destination: $TGZ"
        curl -L --fail -C - --progress-bar -o "$TGZ" "$URL"
    fi

    step "Validating archive integrity"
    if ! tar -tzf "$TGZ" >/dev/null 2>/tmp/tar_check.err; then
        echo "ERROR: '$TGZ' is not a valid gzipped tar." >&2
        sed 's/^/  /' /tmp/tar_check.err >&2
        exit 1
    fi
    rm -f /tmp/tar_check.err
    info "archive looks good"

    LOCAL_SIZE="$(file_size "$TGZ")"
    step "Extracting $(basename "$TGZ") ($(human "$LOCAL_SIZE")) into bots-data/"
    tar -xzf "$TGZ" -C "$BOTS_DIR" --strip-components 1

    for d in default metadata; do
        if [ ! -d "$BOTS_DIR/$d" ]; then
            echo "WARNING: expected folder '$d' missing after extraction." >&2
        fi
    done
fi

# ---------------------------------------------------------------------------
# 3. Populate the named volume from bots-data/
# ---------------------------------------------------------------------------
volume_has_data() {
    docker volume inspect "$VOLUME_NAME" >/dev/null 2>&1 || return 1
    docker run --rm -v "$VOLUME_NAME:/c" alpine test -d /c/default >/dev/null 2>&1
}

step "Checking BOTSv1 named volume"
if volume_has_data && [ "$FORCE" -ne 1 ]; then
    info "$VOLUME_NAME already populated — skipping copy"
    info "(re-run with --force to repopulate)"
else
    info "Splunk can't index the BOTSv1 buckets directly from the Windows bind"
    info "mount (Docker Desktop's gRPC-FUSE share is rejected by validatedb)."
    info "We copy into a native Docker volume instead."

    # Stop container if running so the volume isn't held open
    if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER}\$"; then
        info "stopping $CONTAINER before populating volume"
        docker compose -f "$COMPOSE_FILE" down >/dev/null 2>&1 || true
    fi

    if [ "$FORCE" -eq 1 ] && docker volume inspect "$VOLUME_NAME" >/dev/null 2>&1; then
        info "wiping volume (--force)"
        docker volume rm "$VOLUME_NAME" >/dev/null 2>&1 || true
    fi

    step "Copying bots-data/ into $VOLUME_NAME (~5 min for ~9 GB)"
    docker run --rm \
        -v "$BOTS_DIR:/src:ro" \
        -v "$VOLUME_NAME:/dst" \
        alpine sh -c "set -e; cp -a /src/. /dst/ && rm -f /dst/*.tgz && chown -R ${SPLUNK_UID}:${SPLUNK_UID} /dst && du -sh /dst"
    info "volume populated"
fi

# ---------------------------------------------------------------------------
# 4. Start Splunk
# ---------------------------------------------------------------------------
step "Starting Splunk container"
docker compose -f "$COMPOSE_FILE" up -d

# ---------------------------------------------------------------------------
# 5. Wait for healthy
# ---------------------------------------------------------------------------
step "Waiting for Splunk to become healthy (up to 5 min)"
deadline=$(( $(date +%s) + 300 ))
last_status=""
while [ "$(date +%s)" -lt "$deadline" ]; do
    status="$(docker inspect -f '{{.State.Health.Status}}' "$CONTAINER" 2>/dev/null || echo unknown)"
    if [ "$status" = "healthy" ]; then break; fi
    if [ "$status" != "$last_status" ]; then
        info "status: $status"
        last_status="$status"
    fi
    sleep 5
done
if [ "$status" != "healthy" ]; then
    echo "WARNING: Splunk not healthy after 5 min — check 'docker logs $CONTAINER'" >&2
fi

# ---------------------------------------------------------------------------
# 6. Verify Splunk loaded the app + index has data
# ---------------------------------------------------------------------------
step "Verifying BOTSv1 in Splunk"
sleep 3
app_code="$(curl -ks -u "admin:$SPLUNK_PASS" -o /dev/null -w '%{http_code}' \
    "https://localhost:8089/services/apps/local/botsv1_data_set" || echo 000)"
info "app  : HTTP $app_code (200 = loaded)"

idx_count="$(curl -ks -u "admin:$SPLUNK_PASS" \
    "https://localhost:8089/services/data/indexes/botsv1?output_mode=json" 2>/dev/null \
    | awk -F'"' '/totalEventCount/ {for (i=1;i<=NF;i++) if ($i ~ /totalEventCount/) print $(i+2); exit}')"
info "index: ${idx_count:-?} events"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
cat <<EOF

===============================================================
 Splunk lab is up.
===============================================================
  Web UI   : http://localhost:8000
  Username : admin
  Password : $SPLUNK_PASS

Sample search (set time range to 'All time' — data is from Aug 2016):
  index=botsv1 earliest=0 | stats count by sourcetype

EOF
