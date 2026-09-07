# Microsoft Sentinel SOC & Incident Response Lab

## Objective

Build a cloud-based security operations lab using Microsoft
Sentinel to develop and demonstrate practical experience in
security monitoring, detection engineering, threat hunting,
and incident response.

## Technologies

- Microsoft Azure
- Microsoft Sentinel
- Azure Log Analytics
- Microsoft Entra ID
- Azure Monitor Agent
- Windows 11
- Kusto Query Language (KQL)
- PowerShell
- MITRE ATT&CK

## Planned Scenarios

1. Brute-force authentication detection
2. Suspicious PowerShell activity
3. Privileged account modification
4. Simulated malicious endpoint activity
5. Multi-stage incident correlation

## Project Status

Day 1 - SOC infrastructure deployment
- Created dedicated Azure resource group 
- Deployed Log Analytics workspace 
- Enabled Microsoft Sentinel 
### Day 2 
- Deployed Windows lab endpoint 
- Configured Azure Monitor Agent 
- Created Windows Security Events data collection rule 
- Connected Windows telemetry to Microsoft Sentinel 
- Verified ingestion into the SecurityEvent table 
- Performed initial KQL-based security event hunting 
