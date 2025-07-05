# Security+ SY0-701 Incident Log Analyzer Script
# Detects and analyzes failed logon attempts with Blue Team enhancements

Write-Host "Starting Incident Analysis..." -ForegroundColor Green

# Domain 4.0: Incident Response - Get last 10 failed logon events
$failedLogons = Get-WinEvent -LogName "Security" -MaxEvents 10 -ErrorAction SilentlyContinue | 
    Where-Object { $_.Id -eq 4625 }  # Failed Logon
$failedCount = $failedLogons.Count
Write-Host "Failed Logon Attempts: $failedCount" -ForegroundColor Yellow

# Debug: Inspect properties
foreach ($incident in $failedLogons) {
    Write-Host "Debug: Event Properties for $($incident.TimeCreated):" -ForegroundColor Cyan
    $incident | Format-List -Property *
}

# Temporary placeholder (sorting/analysis disabled)
Write-Host "Incident Analysis Complete!" -ForegroundColor Green