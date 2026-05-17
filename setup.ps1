# One-shot bootstrap for the Splunk + BOTSv1 lab.
#
# Why it's not a simple "compose up": Splunk's validatedb refuses to use
# the BOTSv1 buckets when they live on a Docker Desktop Windows bind
# mount ("unusable filesystem" — gRPC-FUSE lacks the locking/mmap
# semantics Splunk wants). So we stage the dataset in .\bots-data\ on
# the host, then COPY it into a native Docker named volume that the
# Splunk container actually reads from.
#
# Steps (all idempotent):
#   1. download BOTSv1 .tgz into bots-data\  (resume-friendly)
#   2. validate + extract into bots-data\  (skipped if already done)
#   3. copy bots-data\ into the splunk-botsv1 named volume
#      (skipped if the volume already contains a default\ folder)
#   4. docker compose up -d
#   5. wait for the container to become healthy
#   6. verify the botsv1 app + index are visible to Splunk
#
# Usage:
#   .\setup.ps1
#   .\setup.ps1 -Url https://custom.example/botsv1.tgz
#   .\setup.ps1 -SkipDownload
#   .\setup.ps1 -Force                # re-extract AND re-populate volume

param(
    [string]$Url     = "https://s3.amazonaws.com/botsdataset/botsv1/splunk-pre-indexed/botsv1_data_set.tgz",
    [switch]$SkipDownload,
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$repoRoot    = $PSScriptRoot
$composeFile = Join-Path $repoRoot "docker\docker-compose.yml"
$botsDir     = Join-Path $repoRoot "bots-data"
$container   = "splunk-lab"
$splunkPass  = "p@ssw0rd"
# Named volume created by docker compose. Compose prefixes with the
# project name ("name: splunklab" at the top of docker-compose.yml).
$volumeName    = "splunklab_splunk-botsv1"
$splunkUid     = 41812

# Practice challenges under challenges\splunk-bots\ are vendored into this
# repo. They originate from https://github.com/chan2git/splunk-bots — refer
# to that upstream for the original walkthroughs and any updates.

function Write-Step($msg) {
    Write-Host ""
    Write-Host "==> $msg" -ForegroundColor Green
}
function Write-Info($msg) { Write-Host "    $msg" -ForegroundColor DarkGray }

function Format-Size($bytes) {
    if ($bytes -ge 1GB) { return ("{0:N2} GB" -f ($bytes / 1GB)) }
    if ($bytes -ge 1MB) { return ("{0:N2} MB" -f ($bytes / 1MB)) }
    return "$bytes bytes"
}

function Test-VolumeHasData {
    & docker volume inspect $volumeName *> $null
    if ($LASTEXITCODE -ne 0) { return $false }
    & docker run --rm -v "${volumeName}:/c" alpine test -d /c/default *> $null
    return $LASTEXITCODE -eq 0
}

# ---------------------------------------------------------------------------
# Pre-flight
# ---------------------------------------------------------------------------
Write-Step "Pre-flight checks"
foreach ($cmd in @("docker", "tar", "curl.exe")) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        Write-Host "ERROR: '$cmd' not found on PATH." -ForegroundColor Red
        exit 1
    }
}
Write-Info "docker, tar, curl available"

# ---------------------------------------------------------------------------
# 1 + 2. Get the dataset extracted on host (staging area)
# ---------------------------------------------------------------------------
$alreadyExtracted = Test-Path (Join-Path $botsDir "default")
if ($alreadyExtracted -and -not $Force) {
    Write-Step "BOTSv1 already extracted on host — skipping download/extract"
    Write-Info "  found: $botsDir\default\"
    Write-Info "  (re-run with -Force to overwrite)"
} else {
    if ($Force -and $alreadyExtracted) {
        Write-Step "Wiping existing bots-data\ contents (Force)"
        Get-ChildItem -Path $botsDir -Force |
            Where-Object { $_.Name -notin @(".gitkeep", "README.md") -and $_.Extension -ne ".tgz" } |
            Remove-Item -Recurse -Force
    }

    $tgz = Get-ChildItem -Path $botsDir -Filter "*.tgz" -ErrorAction SilentlyContinue |
           Select-Object -First 1

    $remoteSize = $null
    if (-not $SkipDownload) {
        Write-Step "Querying server for archive metadata"
        Write-Info $Url
        $tmpHead = New-TemporaryFile
        $httpCode = & curl.exe -sIL --max-time 30 -o $tmpHead.FullName -w "%{http_code}" $Url
        $headOut = Get-Content $tmpHead.FullName -Raw -ErrorAction SilentlyContinue
        Remove-Item $tmpHead.FullName -ErrorAction SilentlyContinue

        if ($httpCode -notmatch '^(200|301|302)$') {
            Write-Host ""
            Write-Host "ERROR: HEAD request returned HTTP $httpCode — URL is dead or unreachable." -ForegroundColor Red
            Write-Host ""
            Write-Host "Splunk has changed the BOTSv1 download URL several times. Please:"
            Write-Host "  1. Open https://github.com/splunk/botsv1"
            Write-Host "  2. Follow the current Download instructions"
            Write-Host "  3. Save the .tgz into:  $botsDir"
            Write-Host "  4. Re-run .\setup.ps1"
            exit 1
        }
        if ($headOut) {
            $clMatches = [regex]::Matches($headOut, '(?im)^Content-Length:\s*(\d+)\s*$')
            if ($clMatches.Count -gt 0) {
                $remoteSize = [int64]$clMatches[$clMatches.Count - 1].Groups[1].Value
                Write-Info "remote size: $(Format-Size $remoteSize)"
            }
        }
    }

    if ($tgz) {
        Write-Step "Found existing archive in bots-data\"
        Write-Info "path : $($tgz.FullName)"
        $localSize = $tgz.Length
        Write-Info "size : $(Format-Size $localSize)"

        if ($SkipDownload -or (-not $remoteSize)) {
            Write-Info "skipping size comparison"
        } elseif ($localSize -eq $remoteSize) {
            Write-Info "matches remote size — download not needed"
        } elseif ($localSize -lt $remoteSize) {
            $pct = [math]::Round(($localSize * 100.0) / $remoteSize, 1)
            Write-Step "Resuming partial download (have $pct% of file)"
            & curl.exe -L --fail -C - --progress-bar -o $tgz.FullName $Url
            if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
            $tgz = Get-Item $tgz.FullName
        } else {
            Write-Host "WARNING: local file is LARGER than remote — likely corrupt." -ForegroundColor Yellow
            Write-Host "         Delete bots-data\$($tgz.Name) and re-run." -ForegroundColor Yellow
            exit 1
        }
    } else {
        if ($SkipDownload) {
            Write-Host "ERROR: no .tgz found in bots-data\ and -SkipDownload set." -ForegroundColor Red
            exit 1
        }
        $tgzPath = Join-Path $botsDir "botsv1_data_set.tgz"
        Write-Step "Downloading BOTSv1 (~6 GB)"
        Write-Info "destination: $tgzPath"
        & curl.exe -L --fail -C - --progress-bar -o $tgzPath $Url
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        $tgz = Get-Item $tgzPath
    }

    Write-Step "Validating archive integrity"
    & tar -tzf $tgz.FullName *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: '$($tgz.FullName)' is not a valid gzipped tar." -ForegroundColor Red
        exit 1
    }
    Write-Info "archive looks good"

    Write-Step "Extracting $($tgz.Name) ($(Format-Size $tgz.Length)) into bots-data\"
    tar -xzf $tgz.FullName -C $botsDir --strip-components 1
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    foreach ($d in @("default", "metadata")) {
        if (-not (Test-Path (Join-Path $botsDir $d))) {
            Write-Host "WARNING: expected folder '$d' missing after extraction." -ForegroundColor Yellow
        }
    }
}

# ---------------------------------------------------------------------------
# 3. Populate the named volume from bots-data\
# ---------------------------------------------------------------------------
Write-Step "Checking BOTSv1 named volume"
if ((Test-VolumeHasData) -and -not $Force) {
    Write-Info "$volumeName already populated — skipping copy"
    Write-Info "(re-run with -Force to repopulate)"
} else {
    Write-Info "Splunk can't index the BOTSv1 buckets directly from the Windows bind"
    Write-Info "mount (Docker Desktop's gRPC-FUSE share is rejected by validatedb)."
    Write-Info "We copy into a native Docker volume instead."

    $running = & docker ps --format '{{.Names}}' | Where-Object { $_ -eq $container }
    if ($running) {
        Write-Info "stopping $container before populating volume"
        & docker compose -f $composeFile down *> $null
    }

    if ($Force) {
        & docker volume inspect $volumeName *> $null
        if ($LASTEXITCODE -eq 0) {
            Write-Info "wiping volume (Force)"
            & docker volume rm $volumeName *> $null
        }
    }

    Write-Step "Copying bots-data\ into $volumeName (~5 min for ~9 GB)"
    & docker run --rm `
        -v "${botsDir}:/src:ro" `
        -v "${volumeName}:/dst" `
        alpine sh -c "set -e; cp -a /src/. /dst/ && rm -f /dst/*.tgz && chown -R ${splunkUid}:${splunkUid} /dst && du -sh /dst"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: volume populate failed (exit $LASTEXITCODE)" -ForegroundColor Red
        exit $LASTEXITCODE
    }
    Write-Info "volume populated"
}

# ---------------------------------------------------------------------------
# 4. Start Splunk
# ---------------------------------------------------------------------------
Write-Step "Starting Splunk container"
docker compose -f $composeFile up -d
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

# ---------------------------------------------------------------------------
# 5. Wait for healthy
# ---------------------------------------------------------------------------
Write-Step "Waiting for Splunk to become healthy (up to 5 min)"
$deadline = (Get-Date).AddMinutes(5)
$lastStatus = ""
$status = "unknown"
while ((Get-Date) -lt $deadline) {
    try {
        $status = docker inspect -f '{{.State.Health.Status}}' $container 2>$null
    } catch { $status = "unknown" }
    if ($status -eq "healthy") { break }
    if ($status -ne $lastStatus) {
        Write-Info "status: $status"
        $lastStatus = $status
    }
    Start-Sleep -Seconds 5
}
if ($status -ne "healthy") {
    Write-Host "WARNING: Splunk not healthy after 5 min — check 'docker logs $container'" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# 6. Verify Splunk loaded the app + index has data
# ---------------------------------------------------------------------------
Write-Step "Verifying BOTSv1 in Splunk"
Start-Sleep -Seconds 3
$appCode = & curl.exe -ks -u "admin:$splunkPass" -o NUL -w "%{http_code}" `
    "https://localhost:8089/services/apps/local/botsv1_data_set"
Write-Info "app  : HTTP $appCode (200 = loaded)"

$idxJson = & curl.exe -ks -u "admin:$splunkPass" `
    "https://localhost:8089/services/data/indexes/botsv1?output_mode=json"
$idxCount = "?"
if ($idxJson) {
    $m = [regex]::Match($idxJson, '"totalEventCount":\s*"?(\d+)"?')
    if ($m.Success) { $idxCount = $m.Groups[1].Value }
}
Write-Info "index: $idxCount events"

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host " Splunk lab is up." -ForegroundColor Cyan
Write-Host "===============================================================" -ForegroundColor Cyan
Write-Host "  Web UI   : http://localhost:8000"
Write-Host "  Username : admin"
Write-Host "  Password : $splunkPass"
Write-Host ""
Write-Host "Sample search (set time range to 'All time' — data is from Aug 2016):" -ForegroundColor Cyan
Write-Host "  index=botsv1 earliest=0 | stats count by sourcetype"
Write-Host ""
