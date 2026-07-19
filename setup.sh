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
#   7. provision the CTF scoreboard (config file + KV store questions/answers/hints)
#   8. (opt-in, --attackdata) download + ingest the attack_data micro-CTF logs
#
# Usage:
#   ./setup.sh                          # interactive: prompts Normal-vs-CTF mode,
#                                       # then v1/v2/v3/all (no TTY -> skips both
#                                       # prompts, same as today: v1 + CTF on)
#   ./setup.sh --v1 --v2                # multiple datasets
#   ./setup.sh --all                    # v1, v2, v3
#   ./setup.sh --v2 --skip-download     # use the .tgz already in bots-data/botsv2/
#   ./setup.sh --v1 --force             # re-extract AND re-populate v1 volume
#                                       # (also re-imports CTF KV data)
#   ./setup.sh --v1 --url-v1 https://custom.example/botsv1.tgz
#   ./setup.sh --v2 --ctf-questions v2-official   # load docker/ctf_seed_data/v2_official/
#                                                  # instead of the default v2_writeups set
#   ./setup.sh --v1 --ctf-questions none           # install the scoreboard apps but
#                                                   # don't touch KV store data
#
# Practice challenges under challenges/splunk-bots/ are vendored from
# https://github.com/chan2git/splunk-bots — refer to that upstream for
# the original walkthroughs.
#
# CTF scoreboard: splunk/SA-ctf_scoreboard + splunk/SA-ctf_scoreboard_admin,
# vendored under docker/apps/ (trimmed of unused cloudconnectlib/solnlib vendor
# trees that hit Windows MAX_PATH during checkout — neither is imported by the
# web controller). The controller hardcodes its own app names in KV store REST
# paths, so only ONE question/answer set can be loaded at a time (it's a single
# shared 'SA-ctf_scoreboard' KV store, not one per BOTS version).
#
# Question/answer/hint CSVs live in docker/ctf_seed_data/<vN>_<source>/, split
# per BOTS version because the walkthroughs (and the real datasets/indexes)
# are themselves per-version — a v2 question about Cerber ransomware makes no
# sense if only the v1 index is loaded. <source> is 'writeups' (derived from
# https://github.com/chan2git/splunk-bots; BasePoints inferred from the
# question-number hundreds digit, NOT real competition scoring) or 'official'
# (empty placeholder — see the README in each docker/ctf_seed_data/<vN>_official/).
# --ctf-questions picks the set explicitly; left unset, it defaults to
# '<vN>-writeups' for whichever single BOTS version was selected via
# --v1/--v2/--v3 (ambiguous with multiple/no versions selected -> falls back
# to v1-writeups with a note).
#
# The service account the scoreboard uses to fetch answers is just the Splunk
# 'admin' user (see scoreboard_controller.config.example) — fine for a
# single-player lab; a real multi-team event should follow the upstream
# README's svcaccount/ctf_answers_service role instructions instead.
#
# Attack data micro-CTF (--attackdata, opt-in — ~330 MB download): one small
# scenario per malware family from https://github.com/splunk/attack_data,
# ingested into a new 'attack_data' index. Independent of the CTF scoreboard
# above — no scored UI, just real log data plus a question/answer pack at
# challenges/attack-data-ctf/ (questions.md prose-only, full SPL + verified
# answers in SOLUTIONS.md, same convention as challenges/splunk-bots/). See
# attack-data/README.md and the root README's "Attack data micro-CTF"
# section for details. Needs python3 (downloads + manifest parsing).

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
CTF_MODE=""   # v1|v2|v3|v1-official|v2-official|v3-official|none, empty = auto
ATTACKDATA=0  # --attackdata: opt-in ~330MB malware-log micro-CTF ingest

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
        --ctf-questions)
            case "$2" in
                v1|v2|v3|v1-official|v2-official|v3-official|none) CTF_MODE="$2" ;;
                *) echo "Unknown --ctf-questions value: $2 (expected v1|v2|v3|v1-official|v2-official|v3-official|none)"; exit 1 ;;
            esac
            shift 2 ;;
        --attackdata) ATTACKDATA=1; shift ;;
        -h|--help)
            sed -n '2,30p' "$0"; exit 0 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

# If --ctf-questions wasn't given explicitly, ask interactively (when we
# have a terminal) whether this run is plain BOTS-practice or should also
# stand up the CTF scoreboard. Skipped whenever --ctf-questions was passed
# (any value, including "none"), so automation/CI keeps working.
if [ -z "$CTF_MODE" ] && [ -t 0 ]; then
    echo
    echo "Set up mode:"
    echo "  1) Normal — just the BOTS data, for SPL practice / challenges/splunk-bots"
    echo "  2) CTF    — also stand up the CTF scoreboard (scored Q&A UI)"
    printf 'Enter choice [1/2] (default: 2): '
    read -r _mode_sel
    case "$_mode_sel" in
        1) CTF_MODE="none" ;;
        *) ;;  # leave empty -> auto-resolved below to match the BOTS version(s) picked next
    esac
fi

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

# Resolve --ctf-questions default now that BOTS dataset selection is final:
# match whichever single version was selected, else fall back to v1.
if [ -z "$CTF_MODE" ]; then
    _n_sel=0
    [ "$SEL_V1" -eq 1 ] && _n_sel=$((_n_sel + 1))
    [ "$SEL_V2" -eq 1 ] && _n_sel=$((_n_sel + 1))
    [ "$SEL_V3" -eq 1 ] && _n_sel=$((_n_sel + 1))
    if [ "$_n_sel" -eq 1 ]; then
        case "$(selected_list)" in
            v1) CTF_MODE="v1" ;;
            v2) CTF_MODE="v2" ;;
            v3) CTF_MODE="v3" ;;
        esac
    else
        CTF_MODE="v1"
        echo "NOTE: multiple/no BOTS datasets selected — defaulting --ctf-questions to v1" \
            "(override with --ctf-questions v2|v3|... if that's not what you want)"
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

# Same D:\d\foo mangling bug bites native python3.exe (MSYS2_ARG_CONV_EXCL='*'
# stops MSYS converting /d/foo -> D:\foo for it, same as for docker/curl) —
# use this wherever $REPO_ROOT crosses into a python3 argv or an embedded
# python string literal.
REPO_ROOT_WIN="$(to_winpath "$REPO_ROOT")"

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

HAVE_PYTHON3=1
if ! command -v python3 >/dev/null 2>&1; then
    HAVE_PYTHON3=0
    if [ "$CTF_MODE" != "none" ]; then
        echo "WARNING: 'python3' not found on PATH — CTF scoreboard apps will be" >&2
        echo "         installed but question/answer/hint KV data will NOT be" >&2
        echo "         imported. Install python3 and re-run, or pass --ctf-questions none" >&2
        echo "         to silence this warning." >&2
    fi
fi

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
            # curl on Git Bash is the mingw/native build (Schannel), which
            # does NOT understand MSYS paths like /d/... — and MSYS_NO_PATHCONV
            # (set above for docker) stops Git Bash from rewriting them. Hand
            # curl a Windows-form path. No-op on Mac/Linux.
            curl -L --fail -C - --progress-bar -o "$(to_winpath "$TGZ")" "$V_URL"
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
        # See note above: native curl needs a Windows-form output path.
        curl -L --fail -C - --progress-bar -o "$(to_winpath "$TGZ")" "$V_URL"
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

# ---------------------------------------------------------------------------
# CTF scoreboard provisioning
# ---------------------------------------------------------------------------
CTF_CONTROLLER_CONFIG="$REPO_ROOT/docker/apps/SA-ctf_scoreboard/appserver/controllers/scoreboard_controller.config"
CTF_CONTROLLER_EXAMPLE="$REPO_ROOT/docker/apps/SA-ctf_scoreboard/appserver/controllers/scoreboard_controller.config.example"
CTF_SEED_BASE="$REPO_ROOT/docker/ctf_seed_data"

# scoreboard_controller.py reads this file directly off disk (it's not a
# layered Splunk .conf) and hardcodes the app names in its KV store REST
# calls, so both the file location and the 'SA-ctf_scoreboard' /
# 'SA-ctf_scoreboard_admin' folder names are load-bearing.
ensure_ctf_controller_config() {
    if [ -f "$CTF_CONTROLLER_CONFIG" ]; then
        return
    fi
    if [ ! -f "$CTF_CONTROLLER_EXAMPLE" ]; then
        return
    fi
    step "[ctf] generating scoreboard_controller.config"
    # od reads a bounded 16 bytes (unlike `tr < /dev/urandom | head -c24`,
    # which SIGPIPEs tr when head is satisfied — fatal under pipefail).
    local vkey
    vkey="$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')"
    cat > "$CTF_CONTROLLER_CONFIG" <<EOF
[ScoreboardController]
USER = admin
PASS = $SPLUNK_PASS
VKEY = $vkey
EOF
    info "generated (gitignored) — using Splunk 'admin' as the privileged"
    info "answer-check service account, fine for a solo lab"
}

# Args: <csv path>. Prints a JSON array of row objects on stdout, or "[]" if
# the file is missing / header-only.
csv_to_json() {
    # MSYS2_ARG_CONV_EXCL='*' (set above, for docker/curl) also stops MSYS
    # from rewriting /d/... into D:\... for THIS native python3 — without
    # to_winpath it silently 404s and we'd fall into the except branch below.
    python3 -c '
import csv, json, sys
try:
    with open(sys.argv[1], newline="", encoding="utf-8") as f:
        print(json.dumps(list(csv.DictReader(f))))
except FileNotFoundError:
    print("[]")
' "$(to_winpath "$1")"
}

# Args: <app> <collection> <csv path>
import_kv_collection() {
    local app="$1" collection="$2" csvfile="$3"
    local base="https://localhost:8089/servicesNS/nobody/$app/storage/collections/data/$collection"

    local rows
    rows="$(csv_to_json "$csvfile")"
    if [ "$rows" = "[]" ]; then
        info "  $collection: no data rows in $(basename "$csvfile") — skipping"
        return
    fi

    # Splunk pretty-prints an empty collection as "[ ]" (with a space), not
    # the "[]" our own json.dumps produces — compare row counts, not strings.
    # Right after the container reports healthy, the KV store subsystem for a
    # freshly bind-mounted app can still be a few seconds behind splunkd's own
    # REST API, so a query here can transiently 503 / return an error object
    # instead of a list — retry rather than mistake that for "already has 1
    # row" (len() of a 1-key error dict).
    local existing_count attempt
    existing_count="ERR"
    for attempt in 1 2 3 4 5 6; do
        existing_count="$(curl -ks -u "admin:$SPLUNK_PASS" "$base?output_mode=json" 2>/dev/null \
            | python3 -c 'import json,sys
try:
    data = json.load(sys.stdin)
    print(len(data) if isinstance(data, list) else "ERR")
except Exception:
    print("ERR")' 2>/dev/null)"
        [ "$existing_count" != "ERR" ] && [ -n "$existing_count" ] && break
        sleep 5
    done
    if [ "$existing_count" = "ERR" ] || [ -z "$existing_count" ]; then
        echo "WARNING: [ctf] $collection: KV store not responding — skipping import" >&2
        return
    fi
    if [ "$existing_count" -gt 0 ] && [ "$FORCE" -ne 1 ]; then
        info "  $collection: already has $existing_count rows — skipping (--force to reimport)"
        return
    fi
    if [ "$existing_count" -gt 0 ] && [ "$FORCE" -eq 1 ]; then
        curl -ks -u "admin:$SPLUNK_PASS" -X DELETE "$base" >/dev/null
    fi

    # No -o /dev/null: MSYS2_ARG_CONV_EXCL='*' (set above) stops MSYS from
    # rewriting /dev/null to the Windows null device for this native curl —
    # it would fail to write there (exit 23, silenced by -s) right after the
    # POST had already landed server-side. Append the code and split instead.
    local resp http_code
    resp="$(curl -ks -u "admin:$SPLUNK_PASS" -w $'\n%{http_code}' \
        -X POST -H 'Content-Type: application/json' -d "$rows" "$base/batch_save")"
    http_code="${resp##*$'\n'}"
    local n
    n="$(printf '%s' "$rows" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')"
    if [ "$http_code" = "200" ]; then
        info "  $collection: imported $n rows"
    else
        echo "WARNING: [ctf] $collection import returned HTTP $http_code" >&2
    fi
}

provision_ctf_data() {
    # CTF_MODE tokens ('v1', 'v2-official', ...) map onto the
    # docker/ctf_seed_data/<vN>_<source>/ folder naming.
    local seed_folder
    case "$CTF_MODE" in
        v1|v2|v3) seed_folder="${CTF_MODE}_writeups" ;;
        v1-official) seed_folder="v1_official" ;;
        v2-official) seed_folder="v2_official" ;;
        v3-official) seed_folder="v3_official" ;;
        *) echo "internal error: unexpected CTF_MODE '$CTF_MODE'" >&2; return 1 ;;
    esac
    local seed_dir="$CTF_SEED_BASE/$seed_folder"
    if [ ! -d "$seed_dir" ]; then
        echo "WARNING: [ctf] $seed_dir does not exist — skipping KV import" >&2
        return
    fi
    step "[ctf] importing '$CTF_MODE' question/answer/hint set into KV store"
    import_kv_collection "SA-ctf_scoreboard" "ctf_questions" "$seed_dir/ctf_questions.csv"
    import_kv_collection "SA-ctf_scoreboard_admin" "ctf_answers" "$seed_dir/ctf_answers.csv"
    import_kv_collection "SA-ctf_scoreboard_admin" "ctf_hints" "$seed_dir/ctf_hints.csv"

    # Global (not per-version) user/team roster — the welcome/questions
    # pages' get_user_info macro does `lookup ctf_users Username as user`,
    # so without this the Team/DisplayUsername/Teammates panels render
    # blank or literally show unresolved $token$ text.
    import_kv_collection "SA-ctf_scoreboard" "ctf_users" "$CTF_SEED_BASE/ctf_users.csv"

    # Also global: submit_question() in scoreboard_controller.py hard-blocks
    # every answer submission (redirects to user_agreement_required) unless
    # the submitting user has a row in ctf_eulas_accepted — without a seeded
    # ctf_eulas + acceptance record, nobody can ever answer a single question.
    import_kv_collection "SA-ctf_scoreboard" "ctf_eulas" "$CTF_SEED_BASE/ctf_eulas.csv"
    import_kv_collection "SA-ctf_scoreboard" "ctf_eulas_accepted" "$CTF_SEED_BASE/ctf_eulas_accepted.csv"
}

# ---------------------------------------------------------------------------
# Attack-data micro-CTF (opt-in via --attackdata)
# ---------------------------------------------------------------------------
provision_attack_data() {
    if [ "$ATTACKDATA" -ne 1 ]; then
        return
    fi
    if [ "$HAVE_PYTHON3" -eq 0 ]; then
        echo "WARNING: [attackdata] python3 not found — skipping (needed to download files and read the manifest)" >&2
        return
    fi

    step "[attackdata] downloading malware log files (~330MB total, skips files already present)"
    python3 "$(to_winpath "$REPO_ROOT/docker/download_attack_data.py")" "$REPO_ROOT_WIN"

    step "[attackdata] checking attack_data index for existing data"
    local existing_count
    existing_count="$(curl -ks -u "admin:$SPLUNK_PASS" \
        "https://localhost:8089/services/data/indexes/attack_data?output_mode=json" 2>/dev/null \
        | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    print(d["entry"][0]["content"].get("totalEventCount", "0"))
except Exception:
    print("0")' 2>/dev/null || echo 0)"
    existing_count="${existing_count:-0}"

    if [ "$existing_count" -gt 0 ] 2>/dev/null && [ "$FORCE" -ne 1 ]; then
        info "attack_data index already has $existing_count events — skipping ingest (--force to reimport; note: --force does NOT clear this index first, see README for the manual clear command)"
        return
    fi

    step "[attackdata] ingesting via oneshot (one REST call per family log file)"
    python3 -c "
import json
m = json.load(open(r'$REPO_ROOT_WIN\attack-data\manifest.json', encoding='utf-8'))
for e in m:
    print(e['family'] + '\t' + e['log_file'] + '\t' + e['sourcetype'] + '\t' + e['source'])
" | while IFS=$'\t' read -r family logfile st src; do
        container_path="/opt/splunk/attack_data_seed/$logfile"
        # No -o /dev/null -- see the identical fix + comment on the CTF
        # batch_save curl call above (MSYS2_ARG_CONV_EXCL breaks native
        # curl's write to /dev/null).
        # rename-source REPLACES source with $src (the Windows Event Log
        # channel, e.g. XmlWinEventLog:...:Sysmon/Operational) rather than
        # leaving it as the file path — several families share the same
        # channel, so that alone can't tell them apart in SPL. Stash the
        # family in `host` instead (search with host=<family>).
        resp="$(curl -ks -u "admin:$SPLUNK_PASS" -w $'\n%{http_code}' \
            "https://localhost:8089/services/data/inputs/oneshot" \
            --data-urlencode "name=$container_path" \
            --data-urlencode "index=attack_data" \
            --data-urlencode "host=$family" \
            --data-urlencode "sourcetype=$st" \
            --data-urlencode "rename-source=$src")"
        http_code="${resp##*$'\n'}"
        if [ "$http_code" = "201" ] || [ "$http_code" = "200" ]; then
            info "  [$family] queued ($logfile, sourcetype=$st)"
        else
            echo "WARNING: [attackdata] [$family] oneshot returned HTTP $http_code" >&2
        fi
    done
    info "waiting ~15s for indexing to settle..."
    sleep 15
}

# Iterate in stable order
for v in v1 v2 v3; do
    if is_selected "$v"; then
        load_version "$v"
        prepare_host_extract "$v"
        populate_volume "$v"
    fi
done

ensure_ctf_controller_config

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
    # No -o /dev/null: see the CTF/attackdata curl calls above for why that
    # breaks under MSYS2_ARG_CONV_EXCL (native curl can't write the response
    # body to a path it can no longer resolve as the null device).
    app_resp="$(curl -ks -u "admin:$SPLUNK_PASS" -w $'\n%{http_code}' \
        "https://localhost:8089/services/apps/local/$V_APP" || echo $'\n000')"
    app_code="${app_resp##*$'\n'}"
    if [ "$HAVE_PYTHON3" -eq 1 ]; then
        idx_count="$(curl -ks -u "admin:$SPLUNK_PASS" \
            "https://localhost:8089/services/data/indexes/$V_INDEX?output_mode=json" 2>/dev/null \
            | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
    print(d["entry"][0]["content"]["totalEventCount"])
except Exception:
    print("?")' 2>/dev/null || echo "?")"
    else
        idx_count="?"
    fi
    info "[$v] app: HTTP $app_code (200 = loaded)   index: ${idx_count:-?} events"
done

# ---------------------------------------------------------------------------
# 7. Provision CTF scoreboard
# ---------------------------------------------------------------------------
step "[ctf] preparing scoreboard app"
# Plain `docker exec` runs as the image's default 'ansible' user, who can't
# even traverse /opt/splunk/var/log (owned splunk:splunk, mode 750) — use the
# splunk uid so the controller's own RotatingFileHandler can write here too.
docker exec -u "$SPLUNK_UID" "$CONTAINER" mkdir -p /opt/splunk/var/log/scoreboard 2>/dev/null || true
if [ "$CTF_MODE" = "none" ]; then
    info "skipped (--ctf-questions none) — apps installed, KV store untouched"
elif [ "$HAVE_PYTHON3" -eq 0 ]; then
    info "skipped — python3 not found (apps are installed, import manually or install python3 + re-run)"
else
    provision_ctf_data
fi

# ---------------------------------------------------------------------------
# 8. Attack-data micro-CTF (opt-in)
# ---------------------------------------------------------------------------
if [ "$ATTACKDATA" -eq 1 ]; then
    provision_attack_data
fi

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

  CTF scoreboard : http://localhost:8000/en-US/app/SA-ctf_scoreboard/welcome
  Question set   : $CTF_MODE
EOF
if [ "$ATTACKDATA" -eq 1 ]; then
    cat <<EOF
  Attack-data CTF: index=attack_data — see challenges/attack-data-ctf/
EOF
fi
cat <<EOF

EOF
