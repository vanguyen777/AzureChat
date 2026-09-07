# Microsoft Sentinel SOC & Incident Response Lab

## Overview

This project is a hands-on Microsoft Sentinel SOC lab designed to demonstrate
security monitoring, detection engineering, KQL threat hunting, incident
investigation, and MITRE ATT&CK mapping.

The environment uses a Windows Server endpoint connected to Azure Monitor and
Microsoft Sentinel. Controlled security events are generated on the endpoint,
collected into Log Analytics, detected using KQL analytics rules, and
investigated through Sentinel alerts and incidents.

The project currently demonstrates:

- Windows security event collection
- Azure Monitor Agent (AMA) configuration
- Data Collection Rules (DCRs)
- Log Analytics investigation
- Microsoft Sentinel scheduled analytics rules
- KQL detection engineering
- PowerShell Script Block Logging
- Cross-table event correlation
- Alert and incident generation
- MITRE ATT&CK mapping
- SOC-style incident documentation

---

## Lab Architecture

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
     Windows Security DCR          dcr-powershell-logs
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

---

## Environment

### Azure

- Resource Group: `rg-soc-lab`
- Log Analytics Workspace: `law-soc-lab`
- Microsoft Sentinel enabled
- Azure Monitor Agent used for Windows telemetry

### Endpoint

- Host: `LAB-WIN01`
- Operating System: Windows Server 2022 Datacenter Server Core
- Azure Monitor Agent
- Windows Security Event auditing
- PowerShell Script Block Logging

---

## Telemetry

Two primary telemetry paths are used in the lab.

### Windows Security Events

Windows Security telemetry is collected through Azure Monitor Agent and
available through the `SecurityEvent` table.

Events used include:

- Event ID 4624 — Successful logon
- Event ID 4625 — Failed logon
- Event ID 4688 — Process creation

### PowerShell Script Block Logging

PowerShell Operational logging was configured to collect Event ID 4104.

A separate Data Collection Rule was created:

`dcr-powershell-logs`

The DCR collects:

```text
Microsoft-Windows-PowerShell/Operational
Event ID 4104
```

using the `Microsoft-Event` stream.

The resulting telemetry is stored in the Log Analytics `Event` table.

The `RenderedDescription` field contains the PowerShell script block content
used by the detection queries.

---

# Detection Scenarios

## Scenario 1 — Repeated Failed Windows Logons

### Objective

Detect repeated Windows authentication failures that could indicate password
guessing or brute-force activity.

### Data Source

```text
Table: SecurityEvent
Event ID: 4625
```

### Detection Logic

The detection counts failed authentication attempts and identifies activity
where the number of failures reaches the configured threshold.

Example:

```kusto
SecurityEvent
| where EventID == 4625
| summarize
    FailedLogons=count(),
    FirstAttempt=min(TimeGenerated),
    LastAttempt=max(TimeGenerated)
    by Account, Computer, IpAddress
| where FailedLogons >= 5
| extend TimeGenerated = LastAttempt
```

### MITRE ATT&CK

- Credential Access
- T1110 — Brute Force
- T1110.001 — Password Guessing

### Validation

Controlled failed authentication attempts were generated on `LAB-WIN01`.

The events were successfully collected into `SecurityEvent`, and the KQL
detection threshold was reached.

Historical Sentinel alert records were also observed during testing.

### Investigation

See:

`incidents/INC-001-failed-logon-investigation.md`

---

## Scenario 2 — Suspicious PowerShell Base64 Decoding

### Objective

Detect PowerShell script execution involving Base64 decoding.

### Data Source

```text
Log: Microsoft-Windows-PowerShell/Operational
Event ID: 4104
Table: Event
Field: RenderedDescription
```

### Detection Logic

```kusto
Event
| where EventID == 4104
| where RenderedDescription contains "FromBase64String"
| project
    TimeGenerated,
    Computer,
    UserName,
    RenderedDescription
```

The detection identifies PowerShell script blocks containing:

```text
FromBase64String
```

which can be associated with encoded or obfuscated PowerShell activity.

### Simulation

A controlled PowerShell script was executed:

```powershell
$data = [Convert]::FromBase64String("U09DLUxBQi1EQVk0")
$text = [Text.Encoding]::UTF8.GetString($data)
Write-Output $text
```

The decoded marker was:

```text
SOC-LAB-DAY4
```

No malware or malicious payload was executed.

### Sentinel Rule

```text
Name: Suspicious PowerShell Base64 Decoding
Severity: Medium
Frequency: 5 minutes
Lookback: 15 minutes
```

### Validation

The complete telemetry and detection chain was successfully validated:

```text
PowerShell execution
        ↓
Event ID 4104
        ↓
Azure Monitor Agent
        ↓
dcr-powershell-logs
        ↓
Event
        ↓
KQL detection
        ↓
Scheduled analytics rule
        ↓
SecurityAlert
        ↓
SecurityIncident
```

A fresh Sentinel alert and incident were generated during testing.

### MITRE ATT&CK

- Execution
- T1059 — Command and Scripting Interpreter
- T1059.001 — PowerShell

### Investigation

See:

`incidents/INC-002-powershell-investigation.md`

---

## Scenario 3 — Multi-Stage Failed Logon and PowerShell Correlation

### Objective

Develop a higher-confidence detection by correlating authentication failures
with subsequent suspicious PowerShell execution on the same endpoint.

Unlike the previous detections, this scenario correlates telemetry from
multiple Log Analytics tables.

### Data Sources

Authentication activity:

```text
Table: SecurityEvent
Event ID: 4625
```

PowerShell activity:

```text
Table: Event
Event ID: 4104
Indicator: FromBase64String
```

### Correlation Logic

The detection:

1. Identifies failed Windows logons.
2. Identifies PowerShell 4104 events containing `FromBase64String`.
3. Joins the two datasets using the `Computer` field.
4. Requires the PowerShell event to occur after the authentication failure.
5. Requires PowerShell activity to occur within 15 minutes of the failed
   authentication event.

```kusto
SecurityEvent
| where TimeGenerated > ago(30m)
| where Computer contains "LAB-WIN01"
| where EventID == 4625
| project
    SecurityTime=TimeGenerated,
    Computer,
    Account,
    IpAddress,
    LogonType,
    Activity
| join kind=inner (
    Event
    | where TimeGenerated > ago(30m)
    | where Computer contains "LAB-WIN01"
    | where EventID == 4104
    | where RenderedDescription contains "FromBase64String"
    | project
        PowerShellTime=TimeGenerated,
        Computer,
        UserName,
        RenderedDescription
) on Computer
| where PowerShellTime >= SecurityTime
| where PowerShellTime <= SecurityTime + 15m
| project
    TimeGenerated=PowerShellTime,
    Computer,
    SecurityTime,
    Account,
    IpAddress,
    LogonType,
    PowerShellTime,
    UserName,
    RenderedDescription
```

### Sentinel Analytics Rule

```text
Name: Multi-Stage Failed Logons Followed by PowerShell
Kind: Scheduled
Severity: High
Enabled: True

Query Frequency: 5 minutes
Query Period: 30 minutes

Trigger Operator: GreaterThan
Trigger Threshold: 0

Incident Creation: Enabled
Correlation Window: 15 minutes
```

### Validation

A controlled multi-stage sequence was generated on `LAB-WIN01`:

```text
Failed Windows authentication
        ↓
Security Event 4625
        ↓
SecurityEvent
        │
        │ same endpoint + temporal correlation
        │
PowerShell Base64 decoding
        ↓
PowerShell Event 4104
        ↓
Event
        │
        └───────────┐
                    ↓
             KQL inner join
                    ↓
         Scheduled Analytics Rule
                    ↓
              SecurityAlert
                    ↓
             SecurityIncident
```

A fresh `SecurityAlert` and fresh `SecurityIncident` were successfully
generated after validating the final correlation query and enabling incident
creation on the analytics rule.

### MITRE ATT&CK

Authentication stage:

- Credential Access
- T1110 — Brute Force
- T1110.001 — Password Guessing

PowerShell stage:

- Execution
- T1059 — Command and Scripting Interpreter
- T1059.001 — PowerShell

### Classification

**True Positive — Benign / Authorized Simulation**

The rule correctly detected the intentionally generated activity. No
unauthorized compromise occurred.

### Investigation

See:

`incidents/INC-003-multi-stage-correlation.md`

---

# Detection Engineering Lessons

## Cross-Table Correlation

The multi-stage detection demonstrates correlation between two different
Log Analytics tables:

```text
SecurityEvent
      +
    Event
      ↓
join on Computer
      ↓
time-based correlation
```

Rather than alerting on PowerShell activity or authentication failures
independently, the rule combines related activity to provide additional
context.

## Temporal Correlation

The query requires:

```text
PowerShellTime >= SecurityTime
```

and:

```text
PowerShellTime <= SecurityTime + 15 minutes
```

This prevents unrelated PowerShell events on the endpoint from automatically
being correlated with older authentication events.

## PowerShell Telemetry

Windows Security Event ID 4688 was initially investigated for process command
line telemetry.

Although command-line auditing was enabled and command-line data was visible
locally, the required PowerShell command content was not exposed through the
collected `SecurityEvent` records.

PowerShell Script Block Logging was therefore configured as an additional
telemetry source.

Event ID 4104 provided the script content required for the detection.

## Separate Data Collection Rules

The Sentinel Windows Security Events data collection path uses the
`Microsoft-SecurityEvent` stream and populates the `SecurityEvent` table.

PowerShell Operational logs required a separate Windows Event Logs DCR using:

```text
Microsoft-Event
```

which populated the:

```text
Event
```

table.

This resulted in two telemetry sources that could subsequently be correlated
using KQL.

---

# Incident Response Workflow

Each scenario follows a simplified SOC investigation workflow:

```text
Generate controlled activity
        ↓
Validate endpoint telemetry
        ↓
Confirm Log Analytics ingestion
        ↓
Develop KQL detection
        ↓
Validate detection manually
        ↓
Create Sentinel analytics rule
        ↓
Generate fresh activity
        ↓
Validate SecurityAlert
        ↓
Validate SecurityIncident
        ↓
Investigate telemetry
        ↓
Map MITRE ATT&CK
        ↓
Classify incident
        ↓
Document findings
```

All lab-generated incidents are classified as:

**True Positive — Benign / Authorized Simulation**

because the detections correctly identified intentionally generated activity.

---

# Repository Structure

```text
microsoft-sentinel-soc-lab/
│
├── README.md
│
├── architecture/
│
├── detections/
│   ├── failed-logon-detection.kql
│   ├── suspicious-powershell.kql
│   └── multi-stage-logon-powershell-correlation.kql
│
├── incidents/
│   ├── INC-001-failed-logon-investigation.md
│   ├── INC-002-powershell-investigation.md
│   └── INC-003-multi-stage-correlation.md
│
├── automation/
│
├── screenshots/
│   ├── day4-4104-detection.png
│   ├── day4-sentinel-alert.png
│   ├── day4-sentinel-incident.png
│   ├── day5-correlation-kql.png
│   ├── day5-rule-configuration.png
│   ├── day5-security-alert.png
│   └── day5-security-incident.png
│
└── notes/
```

---

# Skills Demonstrated

This project demonstrates practical experience with:

- Microsoft Sentinel
- Microsoft Defender portal
- Azure Monitor
- Log Analytics
- Azure Monitor Agent
- Data Collection Rules
- Windows Security Event logging
- PowerShell Script Block Logging
- Kusto Query Language (KQL)
- Cross-table joins
- Temporal event correlation
- Detection engineering
- Scheduled analytics rules
- Security alert investigation
- Sentinel incident investigation
- MITRE ATT&CK
- Windows authentication telemetry
- PowerShell security monitoring
- Incident documentation
- SOC investigation workflows

---

# Project Status

Completed scenarios:

- [x] Windows telemetry collection
- [x] Repeated failed-logon detection
- [x] PowerShell Script Block Logging collection
- [x] Suspicious PowerShell detection
- [x] Sentinel scheduled analytics rule
- [x] Fresh PowerShell alert generation
- [x] Fresh PowerShell incident generation
- [x] Cross-table KQL correlation
- [x] Multi-stage authentication + PowerShell detection
- [x] Fresh multi-stage Sentinel alert
- [x] Fresh multi-stage Sentinel incident
- [x] MITRE ATT&CK mapping
- [x] Incident investigation documentation

The next phase of the project can extend the lab with additional endpoint or
identity scenarios and basic SOC automation.
