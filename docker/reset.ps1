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
#   - splunk-botsv1 / splunk-botsv2 / splunk-botsv3 volumes (the BOTS
#     indexes — kept so we don't re-copy from bots-data\ on every reset)
#   - bots-data\ on the host
#
# Pass -Full to also wipe the BOTS volumes. The next setup.ps1 run will
# then re-populate the requested datasets from bots-data\<vN>\.
#
# Usage:
#   .\docker\reset.ps1            # fast reset, keep BOTS volumes
#   .\docker\reset.ps1 -Full      # nuke EVERYTHING, requires re-populate
#   .\docker\reset.ps1 -Force     # skip confirmation

param(
    [switch]$Full,
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$composeFile   = Join-Path $PSScriptRoot "docker-compose.yml"
$botsVolumes   = @("splunklab_splunk-botsv1", "splunklab_splunk-botsv2", "splunklab_splunk-botsv3")
$stateVolumes  = @("splunklab_splunk-var", "splunklab_splunk-etc-users")

Write-Host ""
Write-Host "Splunk Lab — Reset" -ForegroundColor Cyan
Write-Host "----------------------------------------"
Write-Host "Compose file : $composeFile"
if ($Full) {
    Write-Host "Mode         : FULL (wipes BOTS volumes too — next setup re-populates)" -ForegroundColor Yellow
} else {
    Write-Host "Mode         : fast  (keeps BOTS volumes — re-uses indexed data)"
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
    Write-Host "==> Removing ALL named volumes (including BOTS data)" -ForegroundColor Green
    docker volume rm ($stateVolumes + $botsVolumes) 2>$null
} else {
    Write-Host "==> Removing only state volumes (keeping BOTS data)" -ForegroundColor Green
    docker volume rm $stateVolumes 2>$null
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
    Write-Host "BOTS volumes were wiped — run setup.ps1 [-V1|-V2|-V3|-All] to re-populate." -ForegroundColor Yellow
} else {
    Write-Host "Tail boot log: docker logs -f splunk-lab"
}
