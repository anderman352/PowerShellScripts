## Security+ SY0-701 Incident Log Analyzer Script
# Detects and analyzes failed logon attempts with Blue Team enhancements

Write-Host "Starting Incident Analysis..." -ForegroundColor Green

# Domain 4.0: Incident Response - Get last 10 failed logon events
$failedLogons = Get-WinEvent -LogName "Security" -MaxEvents 10 -ErrorAction SilentlyContinue | 
    Where-Object { $_.Id -eq 4625 }  # Failed Logon
$failedCount = $failedLogons.Count
Write-Host "Failed Logon Attempts: $failedCount" -ForegroundColor Yellow

# Sort by user name and time with error handling
$sortedLogons = $failedLogons | Sort-Object { 
    $_.Properties[5].Value 
}, { $_.TimeCreated } -ErrorAction SilentlyContinue

foreach ($incident in $sortedLogons) {
    $user = if ($incident.Properties.Count -gt 5) { $incident.Properties[5].Value } else { "Unknown" }
    $time = $incident.TimeCreated
    $sourceIp = if ($incident.Properties.Count -gt 18) { $incident.Properties[18].Value } else { "Unknown" }
    $status = if ($incident.Properties.Count -gt 7) { $incident.Properties[7].Value } else { "Unknown" }
    Write-Host "Incident: Failed Logon by $user at $time from $sourceIp (Status: $status)" -ForegroundColor Yellow

    # Detect pattern (multiple failures on default accounts)
    $isDefaultAccount = $user -in "admin", "local_admin", "sys_admin"
    if ($isDefaultAccount -and $user -ne "Unknown") {
        Write-Host "Alert: Default account $user targeted. Possible password spray/brute force." -ForegroundColor Red
    }

    Write-Host "Investigation: Review account $user, source $sourceIp, and logs for patterns." -ForegroundColor Red
    Write-Host "Mitigation: Lock account $user; isolate $sourceIp; enforce strong passwords." -ForegroundColor Blue
    if ($isDefaultAccount -and $failedCount -ge 3 -and $user -ne "Unknown") {
        Write-Host "Isolation: Block $sourceIp via firewall (e.g., New-NetFirewallRule -Direction Inbound -Action Block -RemoteAddress $sourceIp)." -ForegroundColor Blue
    }
}

if ($failedCount -eq 0) {
    Write-Host "No failed logon incidents detected." -ForegroundColor Green
} else {
    $uniqueUsers = ($failedLogons | ForEach-Object { 
        if ($_.Properties.Count -gt 5) { $_.Properties[5].Value } else { "Unknown" } 
    }) -ne $null -ne "Unknown" | Sort-Object -Unique
    if ($uniqueUsers.Count -ge 3 -and $failedCount -ge 5) {
        Write-Host "Warning: Potential password spray attack detected across $uniqueUsers.Count users with $failedCount attempts." -ForegroundColor Red
    }
}

Write-Host "Incident Analysis Complete!" -ForegroundColor Green