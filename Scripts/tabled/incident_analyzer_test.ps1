# Security+ SY0-701 Incident Log Analyzer Script
# Detects and analyzes failed logon attempts with Blue Team enhancements

Write-Host "Starting Incident Analysis..." -ForegroundColor Green

# Domain 4.0: Incident Response - Get last 10 failed logon events
$failedLogons = Get-WinEvent -LogName "Security" -MaxEvents 10 -ErrorAction SilentlyContinue | 
    Where-Object { $_.Id -eq 4625 }  # Failed Logon
$failedCount = $failedLogons.Count
Write-Host "Failed Logon Attempts: $failedCount" -ForegroundColor Yellow

# Sort by user name and time with error handling
$sortedLogons = $failedLogons | Sort-Object { 
    if ($_.Properties.Count -gt 5) { $_.Properties[5].Value } else { "Unknown" } 
}, { $_.TimeCreated } -ErrorAction SilentlyContinue

# List each failed login
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

# Calculate detailed stats per user with debugging
Write-Host "Debug: Calculating user stats..." -ForegroundColor Cyan
$userStats = $failedLogons | ForEach-Object {
    if ($_.Properties.Count -gt 5) {
        [PSCustomObject]@{
            User = $_.Properties[5].Value
            Time = $_.TimeCreated
            SourceIp = if ($_.Properties.Count -gt 18) { $_.Properties[18].Value } else { "Unknown" }
            Status = if ($_.Properties.Count -gt 7) { $_.Properties[7].Value } else { "Unknown" }
        }
    } else {
        Write-Host "Debug: Skipping event with insufficient properties: $_" -ForegroundColor Cyan
        $null
    }
} | Where-Object { $_ } | Group-Object User | ForEach-Object {
    $groupName = $_.Name
    $events = $failedLogons | Where-Object { $_.Properties.Count -gt 5 -and $_.Properties[5].Value -eq $groupName }
    Write-Host "Debug: Events for $groupName :" -ForegroundColor Cyan
    Write-Host "Debug: Events count: $($events.Count)" -ForegroundColor Cyan
    if ($events) {
        $validEvents = $events | Where-Object { $_.TimeCreated -and $_.TimeCreated -is [DateTime] }
        Write-Host "Debug: Valid events for $groupName : $($validEvents.Count)" -ForegroundColor Cyan
        if ($validEvents.Count -gt 0) {
            try {
                $firstEvent = $validEvents | Sort-Object TimeCreated | Select-Object -First 1
                if (-not $firstEvent) { $firstEvent = $validEvents | Where-Object { $_.TimeCreated } | Select-Object -First 1 }
                $lastEvent = $validEvents | Where-Object { $_.TimeCreated } | Select-Object -Last 1
                if (-not $lastEvent) { $lastEvent = $validEvents | Select-Object -Last 1 }
                if (-not $lastEvent -or -not $lastEvent.TimeCreated) {
                    $lastEvent = $validEvents | Where-Object { $_.TimeCreated -and $_.TimeCreated -is [DateTime] } | Select-Object -Last 1
                }
                [PSCustomObject]@{
                    User = $groupName
                    Count = $_.Count
                    FirstTime = if ($firstEvent -and $firstEvent.TimeCreated) { $firstEvent.TimeCreated } else { [DateTime]::MinValue }
                    LastTime = if ($lastEvent -and $lastEvent.TimeCreated) { $lastEvent.TimeCreated } else { [DateTime]::MinValue }
                    SourceIp = ($validEvents | Select-Object -Unique -ExpandProperty Properties[18].Value -ErrorAction SilentlyContinue | Where-Object { $_ })[0]
                    Status = ($validEvents | Select-Object -Unique -ExpandProperty Properties[7].Value -ErrorAction SilentlyContinue | Where-Object { $_ })[0]
                }
            } catch {
                Write-Host "Debug: Error processing ${groupName}: $_" -ForegroundColor Red
                $null
            }
        } else {
            Write-Host "Debug: No valid events with TimeCreated for ${groupName}." -ForegroundColor Cyan
            $null
        }
    } else {
        Write-Host "Debug: No events for $groupName, skipping." -ForegroundColor Cyan
        $null
    }
} | Where-Object { $_ } | Sort-Object User

# Display table
if ($userStats) {
    $userStats | Format-Table User, Count, FirstTime, LastTime, SourceIp, Status -AutoSize
} else {
    Write-Host "No user stats available to display." -ForegroundColor Yellow
}

if ($failedCount -eq 0) {
    Write-Host "No failed logon incidents detected." -ForegroundColor Green
} else {
    $uniqueUsers = ($failedLogons | ForEach-Object { 
        if ($_.Properties.Count -gt 5) { $_.Properties[5].Value } else { "Unknown" } 
    }) | Where-Object { $null -ne $_ -and $_ -ne "Unknown" } | Sort-Object -Unique
    if ($uniqueUsers.Count -ge 3 -and $failedCount -ge 5) {
        Write-Host "Warning: Potential password spray attack detected across $($uniqueUsers.Count) users with $failedCount attempts." -ForegroundColor Red
    }
}

Write-Host "Incident Analysis Complete!" -ForegroundColor Green