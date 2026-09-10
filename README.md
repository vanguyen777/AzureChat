# Microsoft Sentinel SOC & Incident Response Lab

## Overview

This project is a hands-on Microsoft Sentinel SOC lab designed to demonstrate security monitoring, detection engineering, KQL threat hunting, incident investigation, automation, and MITRE ATT&CK mapping.

The environment uses a Windows Server endpoint connected through Azure Monitor Agent (AMA) to Log Analytics and Microsoft Sentinel. Controlled security events are generated on the endpoint, collected through dedicated Data Collection Rules (DCRs), detected with KQL and scheduled analytics rules, and investigated through Sentinel alerts and incidents.

### What this project demonstrates

- Windows security event collection with AMA
- Data Collection Rules and Log Analytics
- Microsoft Sentinel scheduled analytics rules
- KQL detection engineering and threat hunting
- PowerShell Script Block Logging (Event ID 4104)
- Cross-table and temporal event correlation
- Fresh Sentinel alert and incident validation
- MITRE ATT&CK mapping
- SOC-style incident documentation
- PowerShell telemetry health-check automation

## Lab Architecture

![Microsoft Sentinel SOC lab architecture](architecture/sentinel-soc-lab-architecture.png)

```text
                         LAB-WIN01
                             |
             +---------------+---------------+
             |                               |
             v                               v
     Windows Security Log          PowerShell Operational Log
       Event ID 4625                    Event ID 4104
             |                               |
             +---------------+---------------+
                             |
                             v
                    Azure Monitor Agent
                             |
              +--------------+--------------+
              |                             |
              v                             v
     dcr-windows-security          dcr-powershell-logs
              |                             |
              v                             v
       SecurityEvent                     Event
              |                             |
              +-------------+---------------+
                            |
                            v
                    Log Analytics Workspace
                         law-soc-lab
                            |
                            v
                     Microsoft Sentinel
                            |
                +-----------+-----------+
                |                       |
                v                       v
           KQL Hunting          Scheduled Analytics
                                        |
                                        v
                                  SecurityAlert
                                        |
                                        v
                                  SecurityIncident
```

## Environment

**Azure:** Resource group `rg-soc-lab`, Log Analytics workspace `law-soc-lab`, Microsoft Sentinel, Azure Monitor Agent, and two DCR telemetry paths.

**Endpoint:** `LAB-WIN01`, Windows Server 2022 Datacenter Server Core, Windows Security auditing, and PowerShell Script Block Logging.

## Telemetry

### Windows Security Events

Windows Security telemetry is collected through AMA and `dcr-windows-security` into the `SecurityEvent` table. Events used in the lab include 4624 (successful logon), 4625 (failed logon), and 4688 (process creation).

### PowerShell Script Block Logging

PowerShell Operational Event ID 4104 is collected by the separate `dcr-powershell-logs` DCR using the `Microsoft-Event` stream and stored in the Log Analytics `Event` table. `RenderedDescription` contains the script-block content used by the PowerShell detections.

# Detection Scenarios

## Scenario 1 — Repeated Failed Windows Logons

**Objective:** Detect repeated Windows authentication failures that could indicate password guessing or brute-force activity.

**Data source:** `SecurityEvent`, Event ID 4625.

```kusto
SecurityEvent
| where EventID == 4625
| summarize FailedLogons=count(), FirstAttempt=min(TimeGenerated), LastAttempt=max(TimeGenerated) by Account, Computer, IpAddress
| where FailedLogons >= 5
| extend TimeGenerated = LastAttempt
```

**MITRE ATT&CK:** Credential Access; T1110 Brute Force; T1110.001 Password Guessing.

**Validation:** Controlled failed authentication attempts were generated on `LAB-WIN01`. The events were collected into `SecurityEvent` and the KQL threshold was reached. Historical Sentinel alert records were also observed during testing. This wording intentionally distinguishes the validated current telemetry/KQL result from the historical alert evidence.

Detection: [`detections/failed-logon-detection.kql`](detections/failed-logon-detection.kql)  
Investigation: [`incidents/INC-001-failed-logon-investigation.md`](incidents/INC-001-failed-logon-investigation.md)  
Evidence: [`screenshots/failed-logons-detection.png`](screenshots/failed-logons-detection.png)

## Scenario 2 — Suspicious PowerShell Base64 Decoding

**Objective:** Detect PowerShell script execution involving Base64 decoding.

**Data source:** Microsoft-Windows-PowerShell/Operational, Event ID 4104, Log Analytics `Event`, field `RenderedDescription`.

```kusto
Event
| where EventID == 4104
| where RenderedDescription contains "FromBase64String"
| project TimeGenerated, Computer, UserName, RenderedDescription
```

A controlled PowerShell script decoded the benign marker `SOC-LAB-DAY4`. No malware or malicious payload was executed. The validated signal is the script-block content containing `FromBase64String`; the project does not claim that Event ID 4104 captured the original `-EncodedCommand` launcher argument.

**Sentinel rule:** `Suspicious PowerShell Base64 Decoding`, Medium severity, 5-minute frequency, 15-minute lookback.

**Validation:** A fresh Sentinel `SecurityAlert` and `SecurityIncident` were generated during testing.

**MITRE ATT&CK:** Execution; T1059 Command and Scripting Interpreter; T1059.001 PowerShell.

Detection: [`detections/suspicious-powershell.kql`](detections/suspicious-powershell.kql)  
Investigation: [`incidents/INC-002-powershell-investigation.md`](incidents/INC-002-powershell-investigation.md)  
Evidence: [`4104 detection`](screenshots/day4-4104-detection.png) · [`alert`](screenshots/day4-security-alert.png) · [`incident`](screenshots/day4-security-incident.png)

## Scenario 3 — Multi-Stage Failed Logon and PowerShell Correlation

**Objective:** Develop a higher-confidence detection by correlating a failed Windows authentication event with subsequent suspicious PowerShell activity on the same endpoint.

Authentication telemetry comes from `SecurityEvent` Event ID 4625. PowerShell telemetry comes from `Event` Event ID 4104 with `RenderedDescription` containing `FromBase64String`.

The final rule joins the two tables on `Computer` and requires the PowerShell event to occur after the failed authentication and within 15 minutes. The final stored rule correlates qualifying events; it does **not** require five failed logons.

```kusto
SecurityEvent
| where TimeGenerated > ago(30m)
| where Computer contains "LAB-WIN01"
| where EventID == 4625
| project SecurityTime=TimeGenerated, Computer, Account, IpAddress, LogonType, Activity
| join kind=inner (
    Event
    | where TimeGenerated > ago(30m)
    | where Computer contains "LAB-WIN01"
    | where EventID == 4104
    | where RenderedDescription contains "FromBase64String"
    | project PowerShellTime=TimeGenerated, Computer, UserName, RenderedDescription
) on Computer
| where PowerShellTime >= SecurityTime
| where PowerShellTime <= SecurityTime + 15m
| project TimeGenerated=PowerShellTime, Computer, SecurityTime, Account, IpAddress, LogonType, PowerShellTime, UserName, RenderedDescription
```

**Sentinel rule:** `Multi-Stage Failed Logons Followed by PowerShell`, Scheduled, High severity, enabled, 5-minute frequency, 30-minute lookback, trigger `GreaterThan 0`, incident creation enabled, 15-minute correlation window.

**Validation:** A controlled multi-stage sequence was generated on `LAB-WIN01`. The final query correlated the two telemetry sources, and a fresh `SecurityAlert` and fresh `SecurityIncident` were generated after incident creation was enabled.

**MITRE ATT&CK:** Credential Access / T1110 / T1110.001 and Execution / T1059 / T1059.001.

**Classification:** **True Positive — Benign / Authorized Simulation**.

Detection: [`detections/multi-stage-logon-powershell-correlation.kql`](detections/multi-stage-logon-powershell-correlation.kql)  
Investigation: [`incidents/INC-003-multi-stage-correlation.md`](incidents/INC-003-multi-stage-correlation.md)  
Evidence: [`correlation`](screenshots/day5-correlation2-kql.png) · [`rule configuration`](screenshots/day5-rule-configuration.png) · [`alert`](screenshots/day5-security-alert.png) · [`incident`](screenshots/day5-security-incident.png)

# Detection Engineering Lessons

### Cross-table and temporal correlation

The multi-stage rule correlates `SecurityEvent` and `Event` on `Computer`, then constrains the relationship in time. This adds context beyond alerting independently on authentication failures or PowerShell activity.

### PowerShell telemetry pivot

Windows Security Event ID 4688 was initially investigated for process command-line telemetry. Although command-line auditing was visible locally, the required PowerShell command content was not exposed in the collected `SecurityEvent` records. PowerShell Script Block Logging was therefore configured, and Event ID 4104 supplied the script content needed for detection.

### Separate DCRs

The Sentinel Windows Security Events path uses the `Microsoft-SecurityEvent` stream and populates `SecurityEvent`. PowerShell Operational logs use a separate Windows Event Logs DCR with the `Microsoft-Event` stream, populating `Event`. The resulting telemetry sources are correlated with KQL.

# Automation

[`automation/validate-sentinel-telemetry.ps1`](automation/validate-sentinel-telemetry.ps1) is a lightweight health check for the lab. It queries the Log Analytics workspace and validates recent Windows Security and PowerShell 4104 ingestion from `LAB-WIN01`.

The script is designed to be run from an authenticated Azure PowerShell environment such as Azure Cloud Shell. Keeping the script in GitHub provides a simple operational workflow: clone or pull the repository, run the validator, and confirm the lab telemetry paths before testing detections.

# Incident Response Workflow

```text
Generate controlled activity
        ↓
Validate endpoint telemetry
        ↓
Confirm Log Analytics ingestion
        ↓
Develop and manually validate KQL
        ↓
Create Sentinel analytics rule
        ↓
Generate fresh activity
        ↓
Validate SecurityAlert / SecurityIncident
        ↓
Investigate and map MITRE ATT&CK
        ↓
Classify and document findings
```

Lab-generated incidents are classified as **True Positive — Benign / Authorized Simulation** when the detection correctly identifies intentionally generated activity.

# Repository Structure

```text
AzureChat/
├── README.md
├── architecture/
│   ├── architecture.md
│   └── sentinel-soc-lab-architecture.png
├── automation/
│   └── validate-sentinel-telemetry.ps1
├── detections/
│   ├── failed-logon-detection.kql
│   ├── suspicious-powershell.kql
│   └── multi-stage-logon-powershell-correlation.kql
├── incidents/
│   ├── INC-001-failed-logon-investigation.md
│   ├── INC-002-powershell-investigation.md
│   └── INC-003-multi-stage-correlation.md
└── screenshots/
    ├── failed-logons-detection.png
    ├── day4-4104-detection.png
    ├── day4-security-alert.png
    ├── day4-security-incident.png
    ├── day5-correlation2-kql.png
    ├── day5-rule-configuration.png
    ├── day5-security-alert.png
    └── day5-security-incident.png
```

# Skills Demonstrated

Microsoft Sentinel · Microsoft Defender portal · Azure Monitor · Log Analytics · Azure Monitor Agent · Data Collection Rules · Windows Security logging · PowerShell Script Block Logging · KQL · Cross-table joins · Temporal correlation · Detection engineering · Scheduled analytics rules · Alert and incident investigation · MITRE ATT&CK · PowerShell automation · SOC documentation

# Project Status

- [x] Windows telemetry collection
- [x] Repeated failed-logon detection
- [x] PowerShell Script Block Logging collection
- [x] Suspicious PowerShell detection
- [x] Scheduled analytics rules
- [x] Fresh PowerShell alert and incident generation
- [x] Cross-table KQL correlation
- [x] Multi-stage authentication + PowerShell detection
- [x] Fresh multi-stage alert and incident generation
- [x] MITRE ATT&CK mapping
- [x] Incident investigation documentation
- [x] Architecture documentation
- [x] Telemetry validation automation

## Next Extensions

The lab can be extended with the remaining original Project 1 scope: privileged/account modification monitoring, a safe malware-like simulation, richer investigation evidence, and additional automation/reproducibility work.