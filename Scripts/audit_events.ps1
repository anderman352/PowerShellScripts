# Security+ Audit Events Script
# Tracks recent security events

Write-Host "Starting Audit Events Check..." -ForegroundColor Green

# Domain 4.0: Operations - Get last 10 security events
$events = Get-WinEvent -LogName "Security" -MaxEvents 10 -ErrorAction SilentlyContinue
foreach ($SecEvent in $events) {
    Write-Host "Event ID: $($SecEvent.EventID), Time: $($SecEvent.TimeGenerated), Type: $($SecEvent.EntryType)" -ForegroundColor Yellow
}
# Check certificate store
$certs = Get-ChildItem -Path Cert:\LocalMachine\My
Write-Host "Certificates Found: $($certs.Count)" -ForegroundColor Yellow

Write-Host "Audit Events Check Complete!" -ForegroundColor Green