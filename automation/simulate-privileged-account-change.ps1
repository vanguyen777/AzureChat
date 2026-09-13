# Safe SOC lab simulation for privileged local account modification.
# Run from an elevated 64-bit Windows PowerShell session on LAB-WIN01.

$ErrorActionPreference = 'Stop'
$TestUser = 'soclab-tempadmin'

Write-Host 'Checking audit policy...'
auditpol /get /subcategory:"User Account Management"
auditpol /get /subcategory:"Security Group Management"

Write-Host 'Ensuring required success auditing is enabled...'
auditpol /set /subcategory:"User Account Management" /success:enable | Out-Null
auditpol /set /subcategory:"Security Group Management" /success:enable | Out-Null

if (Get-LocalUser -Name $TestUser -ErrorAction SilentlyContinue) {
    throw "Local user $TestUser already exists. Remove it before running this simulation."
}

$PasswordText = ([guid]::NewGuid().ToString('N') + 'aA1!')
$Password = ConvertTo-SecureString $PasswordText -AsPlainText -Force

Write-Host "Creating local test account: $TestUser"
New-LocalUser -Name $TestUser -Password $Password -Description 'Authorized SOC lab privileged-account simulation' | Out-Null

Write-Host "Adding $TestUser to the local Administrators group"
Add-LocalGroupMember -Group 'Administrators' -Member $TestUser

Write-Host 'Simulation complete.'
Write-Host 'Expected Security events: 4720 (account created) and 4732 (member added to local security-enabled group).'
Write-Host 'The built-in Administrators group SID is S-1-5-32-544.'
Write-Host ''
Write-Host 'Waiting briefly for Security log events to become queryable...'
Start-Sleep -Seconds 3

$events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720,4732; StartTime=(Get-Date).AddMinutes(-10)} -ErrorAction SilentlyContinue

Write-Host 'Recent matching local events:'
if ($events) {
    $events |
        Select-Object TimeCreated, Id, ProviderName, Message |
        Format-List
}
else {
    Write-Warning 'No matching 4720/4732 events were returned yet. Re-run the event query after a few seconds.'
}

Write-Host ''
Write-Host 'After Sentinel validation is complete, clean up with:'
Write-Host "Remove-LocalGroupMember -Group 'Administrators' -Member '$TestUser'"
Write-Host "Remove-LocalUser -Name '$TestUser'"
