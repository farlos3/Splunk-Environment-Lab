# One-shot bootstrap for the Splunk + BOTS lab.
#
# Why it's not a simple "compose up": Splunk's validatedb refuses to use
# the BOTS buckets when they live on a Docker Desktop Windows bind
# mount ("unusable filesystem" — gRPC-FUSE lacks the locking/mmap
# semantics Splunk wants). So we stage each dataset in .\bots-data\<vN>\
# on the host, then COPY it into a native Docker named volume that the
# Splunk container actually reads from.
#
# Steps (all idempotent, per selected dataset):
#   1. download <vN> .tgz into bots-data\<vN>\  (resume-friendly)
#   2. validate + extract into bots-data\<vN>\  (skipped if already done)
#   3. copy bots-data\<vN>\ into the splunk-<vN> named volume
#      (skipped if the volume already contains a default\ folder)
#   4. docker compose up -d
#   5. wait for the container to become healthy
#   6. verify each selected app + index is visible to Splunk
#
# Usage:
#   .\setup.ps1                          # default: BOTSv1 only
#   .\setup.ps1 -V1 -V2                  # multiple datasets
#   .\setup.ps1 -All                     # v1, v2, v3
#   .\setup.ps1 -V2 -SkipDownload        # use the .tgz already in bots-data\botsv2\
#   .\setup.ps1 -V1 -Force               # re-extract AND re-populate v1 volume
#   .\setup.ps1 -V1 -UrlV1 https://custom.example/botsv1.tgz
#
# Practice challenges under challenges\splunk-bots\ are vendored from
# https://github.com/chan2git/splunk-bots — refer to that upstream for
# the original walkthroughs.

param(
    [switch]$V1,
    [switch]$V2,
    [switch]$V3,
    [switch]$All,
    [string]$UrlV1 = "https://s3.amazonaws.com/botsdataset/botsv1/splunk-pre-indexed/botsv1_data_set.tgz",
    [string]$UrlV2 = "https://botsdataset.s3.amazonaws.com/botsv2/botsv2_data_set.tgz",
    [string]$UrlV3 = "https://botsdataset.s3.amazonaws.com/botsv3/botsv3_data_set.tgz",
    [switch]$SkipDownload,
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$repoRoot    = $PSScriptRoot
$composeFile = Join-Path $repoRoot "docker\docker-compose.yml"
$botsBase    = Join-Path $repoRoot "bots-data"
$container   = "splunk-lab"
$splunkPass  = "p@ssw0rd"
$splunkUid   = 41812

# Per-dataset metadata. The HEAD check will catch URLs that have moved;
# if any of these stop working, override with -UrlVN or drop the .tgz
# manually into bots-data\<vN>\ and pass -SkipDownload.
$datasets = @{
    v1 = @{ Url = $UrlV1; Size = "~6 GB"  }
    v2 = @{ Url = $UrlV2; Size = "~28 GB" }
    v3 = @{ Url = $UrlV3; Size = "~3.5 GB" }
}

$selected = New-Object System.Collections.Generic.List[string]
if ($All) { $selected.AddRange([string[]]@("v1","v2","v3")) }
if ($V1 -and -not $selected.Contains("v1")) { $selected.Add("v1") }
if ($V2 -and -not $selected.Contains("v2")) { $selected.Add("v2") }
if ($V3 -and -not $selected.Contains("v3")) { $selected.Add("v3") }
if ($selected.Count -eq 0) { $selected.Add("v1") }   # default

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

function Get-Version($v) {
    [pscustomobject]@{
        Label  = $v
        Url    = $datasets[$v].Url
        Size   = $datasets[$v].Size
        Dir    = Join-Path $botsBase "bots$v"
        Volume = "splunklab_splunk-bots$v"
        App    = "bots${v}_data_set"
        Index  = "bots$v"
    }
}

function Test-VolumeHasData($volumeName) {
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
Write-Info "datasets selected: $($selected -join ', ')"

# ---------------------------------------------------------------------------
# Per-dataset: download → validate → extract → populate volume
# ---------------------------------------------------------------------------

function Invoke-PrepareHostExtract($ds) {
    $v = $ds.Label
    if (-not (Test-Path $ds.Dir)) {
        New-Item -ItemType Directory -Force -Path $ds.Dir | Out-Null
    }

    $alreadyExtracted = Test-Path (Join-Path $ds.Dir "default")
    if ($alreadyExtracted -and -not $Force) {
        Write-Step "[$v] already extracted on host — skipping download/extract"
        Write-Info "  found: $($ds.Dir)\default\"
        Write-Info "  (re-run with -Force to overwrite)"
        return
    }

    if ($Force -and $alreadyExtracted) {
        Write-Step "[$v] wiping existing extracted contents (Force)"
        Get-ChildItem -Path $ds.Dir -Force |
            Where-Object { $_.Name -notin @(".gitkeep", "README.md") -and $_.Extension -ne ".tgz" } |
            Remove-Item -Recurse -Force
    }

    $tgz = Get-ChildItem -Path $ds.Dir -Filter "*.tgz" -ErrorAction SilentlyContinue |
           Select-Object -First 1

    $remoteSize = $null
    if (-not $SkipDownload) {
        Write-Step "[$v] querying server for archive metadata"
        Write-Info $ds.Url
        $tmpHead = New-TemporaryFile
        $httpCode = & curl.exe -sIL --max-time 30 -o $tmpHead.FullName -w "%{http_code}" $ds.Url
        $headOut = Get-Content $tmpHead.FullName -Raw -ErrorAction SilentlyContinue
        Remove-Item $tmpHead.FullName -ErrorAction SilentlyContinue

        if ($httpCode -notmatch '^(200|301|302)$') {
            Write-Host ""
            Write-Host "ERROR: [$v] HEAD request returned HTTP $httpCode — URL is dead or unreachable." -ForegroundColor Red
            Write-Host ""
            Write-Host "Splunk has changed the BOTS download URLs several times. Please:"
            Write-Host "  1. Open https://github.com/splunk/bots$v"
            Write-Host "  2. Follow the current Download instructions"
            Write-Host "  3. Save the .tgz into:  $($ds.Dir)"
            Write-Host "  4. Re-run  .\setup.ps1 -$($v.ToUpper()) -SkipDownload"
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
        Write-Step "[$v] found existing archive"
        Write-Info "path : $($tgz.FullName)"
        $localSize = $tgz.Length
        Write-Info "size : $(Format-Size $localSize)"

        if ($SkipDownload -or (-not $remoteSize)) {
            Write-Info "skipping size comparison"
        } elseif ($localSize -eq $remoteSize) {
            Write-Info "matches remote size — download not needed"
        } elseif ($localSize -lt $remoteSize) {
            $pct = [math]::Round(($localSize * 100.0) / $remoteSize, 1)
            Write-Step "[$v] resuming partial download (have $pct% of file)"
            & curl.exe -L --fail -C - --progress-bar -o $tgz.FullName $ds.Url
            if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
            $tgz = Get-Item $tgz.FullName
        } else {
            Write-Host "WARNING: [$v] local file is LARGER than remote — likely corrupt." -ForegroundColor Yellow
            Write-Host "         Delete $($tgz.FullName) and re-run." -ForegroundColor Yellow
            exit 1
        }
    } else {
        if ($SkipDownload) {
            Write-Host "ERROR: [$v] no .tgz found in $($ds.Dir) and -SkipDownload set." -ForegroundColor Red
            exit 1
        }
        $tgzPath = Join-Path $ds.Dir "bots${v}_data_set.tgz"
        Write-Step "[$v] downloading BOTS$v ($($ds.Size))"
        Write-Info "destination: $tgzPath"
        & curl.exe -L --fail -C - --progress-bar -o $tgzPath $ds.Url
        if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
        $tgz = Get-Item $tgzPath
    }

    Write-Step "[$v] validating archive integrity"
    & tar -tzf $tgz.FullName *> $null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: '$($tgz.FullName)' is not a valid gzipped tar." -ForegroundColor Red
        exit 1
    }
    Write-Info "archive looks good"

    Write-Step "[$v] extracting $($tgz.Name) ($(Format-Size $tgz.Length)) into bots-data\bots$v\"
    tar -xzf $tgz.FullName -C $ds.Dir --strip-components 1
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

    foreach ($d in @("default", "metadata")) {
        if (-not (Test-Path (Join-Path $ds.Dir $d))) {
            Write-Host "WARNING: [$v] expected folder '$d' missing after extraction." -ForegroundColor Yellow
        }
    }
}

function Invoke-PopulateVolume($ds) {
    $v = $ds.Label
    Write-Step "[$v] checking named volume $($ds.Volume)"
    if ((Test-VolumeHasData $ds.Volume) -and -not $Force) {
        Write-Info "already populated — skipping copy"
        Write-Info "(re-run with -Force to repopulate)"
        return
    }

    Write-Info "Splunk can't index BOTS buckets directly from the Windows bind"
    Write-Info "mount (Docker Desktop's gRPC-FUSE share is rejected by validatedb)."
    Write-Info "Copying into a native Docker volume instead."

    $running = & docker ps --format '{{.Names}}' | Where-Object { $_ -eq $container }
    if ($running) {
        Write-Info "stopping $container before populating volume"
        & docker compose -f $composeFile down *> $null
    }

    if ($Force) {
        & docker volume inspect $ds.Volume *> $null
        if ($LASTEXITCODE -eq 0) {
            Write-Info "wiping volume (Force)"
            & docker volume rm $ds.Volume *> $null
        }
    }

    Write-Step "[$v] copying bots-data\bots$v\ into $($ds.Volume)"
    & docker run --rm `
        -v "$($ds.Dir):/src:ro" `
        -v "$($ds.Volume):/dst" `
        alpine sh -c "set -e; cp -a /src/. /dst/ && rm -f /dst/*.tgz && chown -R ${splunkUid}:${splunkUid} /dst && du -sh /dst"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: [$v] volume populate failed (exit $LASTEXITCODE)" -ForegroundColor Red
        exit $LASTEXITCODE
    }
    Write-Info "volume populated"
}

foreach ($v in @("v1", "v2", "v3")) {
    if (-not $selected.Contains($v)) { continue }
    $ds = Get-Version $v
    Invoke-PrepareHostExtract $ds
    Invoke-PopulateVolume   $ds
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
# 6. Verify selected datasets in Splunk
# ---------------------------------------------------------------------------
Write-Step "Verifying selected BOTS datasets in Splunk"
Start-Sleep -Seconds 3
foreach ($v in @("v1", "v2", "v3")) {
    if (-not $selected.Contains($v)) { continue }
    $ds = Get-Version $v
    $appCode = & curl.exe -ks -u "admin:$splunkPass" -o NUL -w "%{http_code}" `
        "https://localhost:8089/services/apps/local/$($ds.App)"
    $idxJson = & curl.exe -ks -u "admin:$splunkPass" `
        "https://localhost:8089/services/data/indexes/$($ds.Index)?output_mode=json"
    $idxCount = "?"
    if ($idxJson) {
        $m = [regex]::Match($idxJson, '"totalEventCount":\s*"?(\d+)"?')
        if ($m.Success) { $idxCount = $m.Groups[1].Value }
    }
    Write-Info "[$v] app: HTTP $appCode (200 = loaded)   index: $idxCount events"
}

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
Write-Host "Sample searches (set time range to 'All time'):" -ForegroundColor Cyan
Write-Host "  index=botsv1 earliest=0 | stats count by sourcetype"
Write-Host "  index=botsv2 earliest=0 | stats count by sourcetype"
Write-Host "  index=botsv3 earliest=0 | stats count by sourcetype"
Write-Host ""
