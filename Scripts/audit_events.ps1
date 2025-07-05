# Security+ Audit Events Script
# Tracks recent security events with Blue Team investigation

Write-Host "Starting Audit Events Check..." -ForegroundColor Green

# Domain 4.0: Operations - Get last 10 security events using Get-WinEvent
$events = Get-WinEvent -LogName "Security" -MaxEvents 10 -ErrorAction SilentlyContinue
foreach ($SecEvent in $events) {
    $isTestEvent = $SecEvent.Id -eq 12345  # Flag custom test event
    $color = if ($isTestEvent) { "Red" } else { "Yellow" }
    Write-Host "Event ID: $($SecEvent.Id), Time: $($SecEvent.TimeCreated), Type: $($SecEvent.LevelDisplayName)" -ForegroundColor $color
    if ($isTestEvent) {
        Write-Host "Investigation: Test event detected (ID 12345). Check for unauthorized access at $($SecEvent.TimeCreated)." -ForegroundColor Red
    } elseif ($SecEvent.Id -eq 4624) {  # Successful logon
        $user = $SecEvent.Properties[1].Value
        Write-Host "Investigation: Logon detected. Verify user $user at $($SecEvent.TimeCreated)." -ForegroundColor Yellow
    }
}

# Domain 2.0: Cryptography - Check certificate store
$certs = Get-ChildItem -Path Cert:\LocalMachine\My
Write-Host "Certificates Found: $($certs.Count)" -ForegroundColor Yellow

Write-Host "Audit Events Check Complete!" -ForegroundColor Green