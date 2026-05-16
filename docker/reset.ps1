# Nuke the Splunk lab and restart with a fresh container.
# Use this when:
#   - Trial license expires (60 days from first boot)
#   - You want to start with empty user-created dashboards/searches
#   - The container has gotten into a weird state
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
# Pass -Full to also wipe splunk-botsv1. The next setup.ps1 run will then
# re-populate it from bots-data/ (~5 min copy).
#
# Usage:
#   .\docker\reset.ps1            # fast reset, keep BOTSv1 volume
#   .\docker\reset.ps1 -Full      # nuke EVERYTHING, requires re-populate
#   .\docker\reset.ps1 -Force     # skip confirmation

param(
    [switch]$Full,
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$composeFile = Join-Path $PSScriptRoot "docker-compose.yml"
$keepVolumes = @("splunklab_splunk-botsv1")

Write-Host ""
Write-Host "Splunk Lab — Reset" -ForegroundColor Cyan
Write-Host "----------------------------------------"
Write-Host "Compose file : $composeFile"
if ($Full) {
    Write-Host "Mode         : FULL (wipes splunk-botsv1 too — next setup re-populates)" -ForegroundColor Yellow
} else {
    Write-Host "Mode         : fast  (keeps splunk-botsv1 — re-uses ~9 GB BOTSv1 data)"
}
Write-Host ""

if (-not $Force) {
    $answer = Read-Host "Continue? [y/N]"
    if ($answer -notmatch '^[Yy]') {
        Write-Host "Aborted." -ForegroundColor Yellow
        exit 0
    }
}

Write-Host "==> Stopping container (without --volumes so we control what's wiped)" -ForegroundColor Green
docker compose -f $composeFile down --remove-orphans

if ($Full) {
    Write-Host "==> Removing ALL named volumes (including splunk-botsv1)" -ForegroundColor Green
    docker volume rm splunklab_splunk-var splunklab_splunk-etc-users splunklab_splunk-botsv1 2>$null
} else {
    Write-Host "==> Removing only state volumes (keeping splunk-botsv1)" -ForegroundColor Green
    docker volume rm splunklab_splunk-var splunklab_splunk-etc-users 2>$null
}

Write-Host "==> Starting fresh Splunk container" -ForegroundColor Green
docker compose -f $composeFile up -d

Write-Host ""
Write-Host "Splunk is booting (60-120 seconds)." -ForegroundColor Cyan
Write-Host "  Web UI   : http://localhost:8000"
Write-Host "  Username : admin"
Write-Host "  Password : p@ssw0rd"
Write-Host ""
if ($Full) {
    Write-Host "BOTSv1 volume was wiped — run setup.ps1 to re-populate (~5 min)." -ForegroundColor Yellow
} else {
    Write-Host "Tail boot log: docker logs -f splunk-lab"
}
