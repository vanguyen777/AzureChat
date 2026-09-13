# Deploy the Project 1 local Administrators group membership analytics rule.
# Run from an authenticated Azure PowerShell environment such as Azure Cloud Shell.

$ErrorActionPreference = 'Stop'
$ResourceGroupName = 'rg-soc-lab'
$WorkspaceName = 'law-soc-lab'
$ApiVersion = '2025-09-01'
$RuleId = [guid]::NewGuid().Guid

$Workspace = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $WorkspaceName
$WorkspaceResourceId = $Workspace.ResourceId
$RuleUri = "$WorkspaceResourceId/providers/Microsoft.SecurityInsights/alertRules/$RuleId`?api-version=$ApiVersion"

$Query = @'
SecurityEvent
| where TimeGenerated > ago(30m)
| where Computer contains "LAB-WIN01"
| where EventID == 4732
| where TargetSid == "S-1-5-32-544"
| project TimeGenerated, Computer, SubjectAccount, MemberName, MemberSid, TargetAccount, TargetSid, Activity
'@

$Body = @{
    kind = 'Scheduled'
    properties = @{
        displayName = 'Local Account Added to Administrators Group'
        description = 'Detects a member added to the built-in local Administrators group on LAB-WIN01 using Windows Security Event ID 4732.'
        severity = 'High'
        enabled = $true
        tactics = @('PrivilegeEscalation')
        techniques = @('T1098')
        query = $Query
        queryFrequency = 'PT5M'
        queryPeriod = 'PT30M'
        triggerOperator = 'GreaterThan'
        triggerThreshold = 0
        suppressionDuration = 'PT5H'
        suppressionEnabled = $false
        eventGroupingSettings = @{
            aggregationKind = 'AlertPerResult'
        }
        incidentConfiguration = @{
            createIncident = $true
        }
    }
} | ConvertTo-Json -Depth 20 -Compress

$Response = Invoke-AzRestMethod -Path $RuleUri -Method PUT -Payload $Body
$Result = $Response.Content | ConvertFrom-Json

Write-Host "Rule deployed: $($Result.properties.displayName)"
Write-Host "Rule ID: $($Result.name)"
Write-Host "Enabled: $($Result.properties.enabled)"
Write-Host "Severity: $($Result.properties.severity)"
Write-Host "Incident creation: $($Result.properties.incidentConfiguration.createIncident)"
