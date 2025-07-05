# Security+ SY0-701 Incident Log Analyzer Script
# Detects and analyzes failed logon attempts for incident response

Write-Host "Starting Incident Analysis..." -ForegroundColor Green

# Domain 4.0: Incident Response - Get last 10 failed logon events
$failedLogons = Get-WinEvent -LogName "Security" -MaxEvents 10 -ErrorAction SilentlyContinue | 
    Where-Object { $_.Id -eq 4625 }  # Failed Logon
$failedCount = $failedLogons.Count
Write-Host "Failed Logon Attempts: $failedCount" -ForegroundColor Yellow

foreach ($incident in $failedLogons) {
    $user = $incident.Properties[5].Value  # Target User Name
    $time = $incident.TimeCreated
    $sourceIp = $incident.Properties[18].Value  # IP Address
    $status = $incident.Properties[7].Value    # Logon Status
    Write-Host "Incident: Failed Logon by $user at $time from $sourceIp (Status: $status)" -ForegroundColor Yellow
    Write-Host "Investigation: Possible brute force attack. Review account $user, source $sourceIp, and security logs." -ForegroundColor Red
    Write-Host "Mitigation: Lock account if repeated; update password policy." -ForegroundColor Red
}

if ($failedCount -eq 0) {
    Write-Host "No failed logon incidents detected." -ForegroundColor Green
}

Write-Host "Incident Analysis Complete!" -ForegroundColor Green