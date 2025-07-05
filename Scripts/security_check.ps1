# Security+ Certification Test Script
# Checks user accounts, password policies, and firewall status

Write-Host "Starting Security Check..." -ForegroundColor Green

# Domain 1.0: Attacks, Threats, and Vulnerabilities - Check enabled users
$users = Get-LocalUser | Where-Object { $_.Enabled -eq $true }
foreach ($user in $users) {
    $lastLogon = $user.LastLogon
    Write-Host "User: $($user.Name), Enabled: $($user.Enabled), Last Logon: $lastLogon" -ForegroundColor Yellow
}

# Domain 3.0: Implementation - Check password policy via registry
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$minPasswordLength = (Get-ItemProperty -Path $regPath -Name "MinimumPasswordLength" -ErrorAction SilentlyContinue).MinimumPasswordLength
$maxPasswordAge = (Get-ItemProperty -Path $regPath -Name "MaximumPasswordAge" -ErrorAction SilentlyContinue).MaximumPasswordAge
if ($minPasswordLength) { $minPasswordLength = "$minPasswordLength characters" } else { $minPasswordLength = "Not set" }
if ($maxPasswordAge) { $maxPasswordAge = "$maxPasswordAge days" } else { $maxPasswordAge = "Not set" }
Write-Host "Password Policy - Min Length: $minPasswordLength, Max Age: $maxPasswordAge" -ForegroundColor Yellow

# Domain 4.0: Operations - Check firewall status
$firewall = Get-NetFirewallProfile | Where-Object { $_.Name -eq "Domain" }
Write-Host "Firewall Domain Profile: Enabled=$($firewall.Enabled), Default Action: $($firewall.DefaultInboundAction)" -ForegroundColor Yellow

# Domain 5.0: Governance - Check Windows Defender status
$defender = Get-MpComputerStatus
Write-Host "Windows Defender: Real-time Protection Enabled=$($defender.RealTimeProtectionEnabled)" -ForegroundColor Yellow

Write-Host "Security Check Complete!" -ForegroundColor Green