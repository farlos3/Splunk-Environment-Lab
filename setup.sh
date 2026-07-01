#!/usr/bin/env bash
# One-shot bootstrap for the Splunk + BOTS lab. Mirrors setup.ps1.
#
# Why it's not a simple "compose up": Splunk's validatedb refuses to use
# the BOTS buckets when they live on a Docker Desktop Windows bind
# mount ("unusable filesystem" — gRPC-FUSE lacks the locking/mmap
# semantics Splunk wants). So we stage each dataset in ../bots-data/<vN>/
# on the host, then COPY it into a native Docker named volume that the
# Splunk container actually reads from.
#
# Steps (all idempotent, per selected dataset):
#   1. download <vN> .tgz into bots-data/<vN>/  (resume-friendly)
#   2. validate + extract into bots-data/<vN>/  (skipped if already done)
#   3. copy bots-data/<vN>/ into the splunk-<vN> named volume
#      (skipped if the volume already contains a default/ folder)
#   4. docker compose up -d
#   5. wait for the container to become healthy
#   6. verify each selected app + index is visible to Splunk
#
# Usage:
#   ./setup.sh                          # interactive: prompts for v1/v2/v3/all
#                                       # (no TTY -> defaults to v1)
#   ./setup.sh --v1 --v2                # multiple datasets
#   ./setup.sh --all                    # v1, v2, v3
#   ./setup.sh --v2 --skip-download     # use the .tgz already in bots-data/botsv2/
#   ./setup.sh --v1 --force             # re-extract AND re-populate v1 volume
#   ./setup.sh --v1 --url-v1 https://custom.example/botsv1.tgz
#
# Practice challenges under challenges/splunk-bots/ are vendored from
# https://github.com/chan2git/splunk-bots — refer to that upstream for
# the original walkthroughs.

set -euo pipefail

# ---------------------------------------------------------------------------
# Windows / Git Bash compatibility
# ---------------------------------------------------------------------------
# Git Bash on Windows (MSYS / MSYS2) auto-rewrites Unix-style paths in
# command arguments to Windows form. That mangles `docker run -v
# host:/container` mounts because the `:/container` half looks like a
# path to MSYS. Disabling both knobs is a no-op on Mac, Linux, and WSL
# but is mandatory for Git Bash.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

# ---------------------------------------------------------------------------
# Per-dataset configuration. The HEAD check will catch URLs that have
# moved; if any of these stop working, override with --url-vN or drop the
# .tgz manually into bots-data/<vN>/ and pass --skip-download.
# ---------------------------------------------------------------------------
URL_V1="https://s3.amazonaws.com/botsdataset/botsv1/splunk-pre-indexed/botsv1_data_set.tgz"
URL_V2="https://botsdataset.s3.amazonaws.com/botsv2/botsv2_data_set.tgz"
URL_V3="https://botsdataset.s3.amazonaws.com/botsv3/botsv3_data_set.tgz"

SIZE_V1="~6 GB"
SIZE_V2="~28 GB"
SIZE_V3="~3.5 GB"

SKIP_DOWNLOAD=0
FORCE=0
# macOS ships bash 3.2 which lacks associative arrays. Use plain flags
# so the same script runs on Mac, Linux, Git Bash, and WSL.
SEL_V1=0
SEL_V2=0
SEL_V3=0

is_selected() {
    case "$1" in
        v1) [ "$SEL_V1" -eq 1 ] ;;
        v2) [ "$SEL_V2" -eq 1 ] ;;
        v3) [ "$SEL_V3" -eq 1 ] ;;
        *) return 1 ;;
    esac
}

selected_list() {
    local out=""
    [ "$SEL_V1" -eq 1 ] && out="$out v1"
    [ "$SEL_V2" -eq 1 ] && out="$out v2"
    [ "$SEL_V3" -eq 1 ] && out="$out v3"
    echo "${out# }"
}

any_selected() {
    [ "$SEL_V1" -eq 1 ] || [ "$SEL_V2" -eq 1 ] || [ "$SEL_V3" -eq 1 ]
}

while [ $# -gt 0 ]; do
    case "$1" in
        --v1)  SEL_V1=1; shift ;;
        --v2)  SEL_V2=1; shift ;;
        --v3)  SEL_V3=1; shift ;;
        --all) SEL_V1=1; SEL_V2=1; SEL_V3=1; shift ;;
        --url-v1) URL_V1="$2"; shift 2 ;;
        --url-v2) URL_V2="$2"; shift 2 ;;
        --url-v3) URL_V3="$2"; shift 2 ;;
        --skip-download) SKIP_DOWNLOAD=1; shift ;;
        --force) FORCE=1; shift ;;
        -h|--help)
            sed -n '2,30p' "$0"; exit 0 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

# If no dataset flags were given, ask interactively (when we have a
# terminal). Passing --v1/--v2/--v3/--all still skips the prompt, so
# automation/CI keeps working. With no TTY (piped input), fall back to
# the historical default of v1 only.
if ! any_selected; then
    if [ -t 0 ]; then
        echo
        echo "Which BOTS dataset(s) do you want to set up?"
        echo "  v1   ($SIZE_V1)   web intrusion + Cerber ransomware"
        echo "  v2   ($SIZE_V2)  APT / advanced-threat scenario"
        echo "  v3   ($SIZE_V3) AWS + O365 cloud / identity"
        echo "  all  (all three)"
        printf 'Enter choice(s) [e.g. v1 , "v1 v3", or all] (default: v1): '
        read -r _sel
        [ -z "$_sel" ] && _sel=v1
        case "$_sel" in
            a|A|all|ALL) SEL_V1=1; SEL_V2=1; SEL_V3=1 ;;
            *)
                case "$_sel" in *v1*|*V1*) SEL_V1=1 ;; esac
                case "$_sel" in *v2*|*V2*) SEL_V2=1 ;; esac
                case "$_sel" in *v3*|*V3*) SEL_V3=1 ;; esac
                ;;
        esac
        if ! any_selected; then
            echo "  (couldn't parse a selection — defaulting to v1)"
            SEL_V1=1
        fi
    else
        SEL_V1=1
    fi
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$REPO_ROOT/docker/docker-compose.yml"
BOTS_BASE="$REPO_ROOT/bots-data"
CONTAINER="splunk-lab"
SPLUNK_PASS="p@ssw0rd"
SPLUNK_UID=41812

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

# `docker` on Windows is a native .exe — it sees the Unix-form path
# `/d/foo` that bash hands it and treats it as drive-relative `D:\d\foo`.
# Convert paths to Windows form before passing them to docker. No-op on
# Mac, Linux, and WSL (where docker is a Linux binary that understands
# /d/... just fine).
to_winpath() {
    case "$(uname -s)" in
        MINGW*|MSYS*|CYGWIN*) cygpath -w "$1" ;;
        *) printf '%s\n' "$1" ;;
    esac
}

# Resolve per-version metadata. Sets these globals: V_URL, V_SIZE,
# V_DIR, V_VOLUME, V_APP, V_INDEX.
load_version() {
    local v="$1"
    case "$v" in
        v1) V_URL="$URL_V1"; V_SIZE="$SIZE_V1" ;;
        v2) V_URL="$URL_V2"; V_SIZE="$SIZE_V2" ;;
        v3) V_URL="$URL_V3"; V_SIZE="$SIZE_V3" ;;
        *) echo "internal error: unknown version '$v'" >&2; exit 1 ;;
    esac
    V_DIR="$BOTS_BASE/bots${v}"
    V_VOLUME="splunklab_splunk-bots${v}"
    V_APP="bots${v}_data_set"
    V_INDEX="bots${v}"
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

# `docker info` is the cheapest call that actually talks to the daemon.
# A bare `docker --version` only checks the CLI binary and would not
# catch the common "Docker Desktop not started" case.
if ! docker info >/dev/null 2>&1; then
    case "$(uname -s)" in
        Darwin)  start_hint="Open Docker Desktop from Applications (or: open -a Docker)" ;;
        Linux)   start_hint="Start the daemon: sudo systemctl start docker" ;;
        MINGW*|MSYS*|CYGWIN*) start_hint="Launch Docker Desktop from the Start menu" ;;
        *)       start_hint="Make sure Docker Desktop / dockerd is running" ;;
    esac
    cat >&2 <<EOF
ERROR: Docker daemon is not reachable.
  $start_hint
  Then wait until the whale icon stops animating and re-run this script.
EOF
    exit 1
fi
info "docker daemon reachable"

info "datasets selected: $(selected_list)"

# ---------------------------------------------------------------------------
# Per-dataset: download → validate → extract → populate volume
# ---------------------------------------------------------------------------

prepare_host_extract() {
    # Args: <version-label>
    # Uses globals from load_version.
    local v="$1"
    mkdir -p "$V_DIR"

    if [ -d "$V_DIR/default" ] && [ "$FORCE" -ne 1 ]; then
        step "[$v] already extracted on host — skipping download/extract"
        info "  found: $V_DIR/default/"
        info "  (re-run with --force to overwrite)"
        return
    fi

    if [ "$FORCE" -eq 1 ] && [ -d "$V_DIR/default" ]; then
        step "[$v] wiping existing extracted contents (--force)"
        find "$V_DIR" -mindepth 1 -maxdepth 1 \
            ! -name '.gitkeep' ! -name 'README.md' ! -name '*.tgz' \
            -exec rm -rf {} +
    fi

    local TGZ
    TGZ="$(find "$V_DIR" -maxdepth 1 -type f \( -name '*.tgz' -o -name '*.tar.gz' \) | head -n 1)"

    local REMOTE_SIZE=""
    if [ "$SKIP_DOWNLOAD" -ne 1 ]; then
        step "[$v] querying server for archive metadata"
        info "$V_URL"
        local HEAD_OUT http_code
        HEAD_OUT="$(curl -sIL --max-time 30 "$V_URL" || true)"
        http_code="$(echo "$HEAD_OUT" | awk '/^HTTP/ {code=$2} END {print code}')"
        REMOTE_SIZE="$(echo "$HEAD_OUT" | tr -d '\r' | awk 'tolower($1)=="content-length:" {print $2}' | tail -n 1)"

        if [[ ! "$http_code" =~ ^(200|301|302)$ ]]; then
            cat >&2 <<EOF

ERROR: [$v] HEAD request returned HTTP $http_code — URL is dead or unreachable.

Splunk has changed the BOTS download URLs several times. Please:
  1. Open https://github.com/splunk/bots${v}
  2. Follow the current Download instructions
  3. Save the .tgz into:  $V_DIR
  4. Re-run ./setup.sh --${v} --skip-download
EOF
            exit 1
        fi
        if [ -n "$REMOTE_SIZE" ]; then
            info "remote size: $(human "$REMOTE_SIZE")"
        fi
    fi

    if [ -n "$TGZ" ]; then
        step "[$v] found existing archive"
        info "path : $TGZ"
        local LOCAL_SIZE
        LOCAL_SIZE="$(file_size "$TGZ")"
        info "size : $(human "$LOCAL_SIZE")"

        if [ "$SKIP_DOWNLOAD" -eq 1 ] || [ -z "$REMOTE_SIZE" ]; then
            info "skipping size comparison"
        elif [ "$LOCAL_SIZE" -eq "$REMOTE_SIZE" ]; then
            info "matches remote size — download not needed"
        elif [ "$LOCAL_SIZE" -lt "$REMOTE_SIZE" ]; then
            local pct
            pct="$(awk "BEGIN {printf \"%.1f\", $LOCAL_SIZE*100/$REMOTE_SIZE}")"
            step "[$v] resuming partial download (have ${pct}% of file)"
            curl -L --fail -C - --progress-bar -o "$TGZ" "$V_URL"
        else
            echo "WARNING: [$v] local file is LARGER than remote — likely corrupt." >&2
            echo "         Delete $TGZ and re-run." >&2
            exit 1
        fi
    else
        if [ "$SKIP_DOWNLOAD" -eq 1 ]; then
            echo "ERROR: [$v] no .tgz found in $V_DIR and --skip-download set." >&2
            exit 1
        fi
        TGZ="$V_DIR/bots${v}_data_set.tgz"
        step "[$v] downloading BOTS${v} ($V_SIZE)"
        info "destination: $TGZ"
        curl -L --fail -C - --progress-bar -o "$TGZ" "$V_URL"
    fi

    step "[$v] validating archive integrity"
    if ! tar -tzf "$TGZ" >/dev/null 2>/tmp/tar_check.err; then
        echo "ERROR: '$TGZ' is not a valid gzipped tar." >&2
        sed 's/^/  /' /tmp/tar_check.err >&2
        exit 1
    fi
    rm -f /tmp/tar_check.err
    info "archive looks good"

    local LOCAL_SIZE
    LOCAL_SIZE="$(file_size "$TGZ")"
    step "[$v] extracting $(basename "$TGZ") ($(human "$LOCAL_SIZE")) into bots-data/bots${v}/"
    tar -xzf "$TGZ" -C "$V_DIR" --strip-components 1

    for d in default metadata; do
        if [ ! -d "$V_DIR/$d" ]; then
            echo "WARNING: [$v] expected folder '$d' missing after extraction." >&2
        fi
    done
}

populate_volume() {
    # Args: <version-label>
    local v="$1"

    volume_has_data() {
        docker volume inspect "$V_VOLUME" >/dev/null 2>&1 || return 1
        docker run --rm -v "$V_VOLUME:/c" alpine test -d /c/default >/dev/null 2>&1
    }

    step "[$v] checking named volume $V_VOLUME"
    if volume_has_data && [ "$FORCE" -ne 1 ]; then
        info "already populated — skipping copy"
        info "(re-run with --force to repopulate)"
        return
    fi

    info "Splunk can't index BOTS buckets directly from the Windows bind"
    info "mount (Docker Desktop's gRPC-FUSE share is rejected by validatedb)."
    info "Copying into a native Docker volume instead."

    if docker ps --format '{{.Names}}' | grep -q "^${CONTAINER}\$"; then
        info "stopping $CONTAINER before populating volume"
        docker compose -f "$(to_winpath "$COMPOSE_FILE")" down >/dev/null 2>&1 || true
    fi

    if [ "$FORCE" -eq 1 ] && docker volume inspect "$V_VOLUME" >/dev/null 2>&1; then
        info "wiping volume (--force)"
        docker volume rm "$V_VOLUME" >/dev/null 2>&1 || true
    fi

    step "[$v] copying bots-data/bots${v}/ into $V_VOLUME"
    docker run --rm \
        -v "$(to_winpath "$V_DIR"):/src:ro" \
        -v "$V_VOLUME:/dst" \
        alpine sh -c "set -e; cp -a /src/. /dst/ && rm -f /dst/*.tgz && chown -R ${SPLUNK_UID}:${SPLUNK_UID} /dst && du -sh /dst"
    info "volume populated"
}

# Iterate in stable order
for v in v1 v2 v3; do
    if is_selected "$v"; then
        load_version "$v"
        prepare_host_extract "$v"
        populate_volume "$v"
    fi
done

# ---------------------------------------------------------------------------
# 4. Start Splunk
# ---------------------------------------------------------------------------
step "Starting Splunk container"
docker compose -f "$(to_winpath "$COMPOSE_FILE")" up -d

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
# 6. Verify selected datasets in Splunk
# ---------------------------------------------------------------------------
step "Verifying selected BOTS datasets in Splunk"
sleep 3
for v in v1 v2 v3; do
    if ! is_selected "$v"; then continue; fi
    load_version "$v"
    app_code="$(curl -ks -u "admin:$SPLUNK_PASS" -o /dev/null -w '%{http_code}' \
        "https://localhost:8089/services/apps/local/$V_APP" || echo 000)"
    idx_count="$(curl -ks -u "admin:$SPLUNK_PASS" \
        "https://localhost:8089/services/data/indexes/$V_INDEX?output_mode=json" 2>/dev/null \
        | awk -F'"' '/totalEventCount/ {for (i=1;i<=NF;i++) if ($i ~ /totalEventCount/) print $(i+2); exit}')"
    info "[$v] app: HTTP $app_code (200 = loaded)   index: ${idx_count:-?} events"
done

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

EOF
