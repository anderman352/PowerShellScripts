$accounts = "admin", "local_admin", "sys_admin"
foreach ($account in $accounts) {
    $attempts = Get-Random -Minimum 3 -Maximum 7  # Random 3-6 attempts
    for ($i = 0; $i -lt $attempts; $i++) {
        $password = ConvertTo-SecureString "WrongPassword123" -AsPlainText -Force
        $credential = New-Object System.Management.Automation.PSCredential ($account, $password)
        Start-Process powershell -Credential $credential -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500  # Brief delay
    }
}