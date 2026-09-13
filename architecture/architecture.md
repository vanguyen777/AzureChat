# Microsoft Sentinel SOC Lab Architecture

## Environment

| Component | Value |
|---|---|
| Resource group | `rg-soc-lab` |
| Log Analytics workspace | `law-soc-lab` |
| Region | East US |
| SIEM | Microsoft Sentinel |
| Endpoint | `LAB-WIN01` — deployed and validated |
| Agent | Azure Monitor Agent (AMA) |

## Telemetry data flow

The endpoint produces two Windows telemetry streams collected by AMA and routed through separate Data Collection Rules:

1. Windows Security events → `dcr-windows-security` → `Microsoft-SecurityEvent` → Log Analytics `SecurityEvent`
2. PowerShell Operational events → `dcr-powershell-logs` → `Microsoft-Event` → Log Analytics `Event`

Microsoft Sentinel queries both tables with KQL detection rules. Matching results create scheduled-rule alerts and, where configured, incidents for investigation.

## Detection and response path

```text
LAB-WIN01
  ├─ Windows Security Log
  │    └─ AMA → dcr-windows-security → SecurityEvent
  └─ PowerShell Operational Log
       └─ AMA → dcr-powershell-logs → Event

SecurityEvent + Event
  └─ KQL hunting and scheduled analytics rules
       └─ SecurityAlert → SecurityIncident → investigation and MITRE ATT&CK mapping
```

## Implemented event coverage

- Windows Security: 4624, 4625, 4688, 4720, 4722, 4724, 4725, 4732, 4733
- PowerShell Script Block Logging: 4104
- Cross-table temporal correlation: `SecurityEvent` + `Event`
- SID-based correlation: account creation `TargetSid` → privileged group membership `MemberSid`
- Process creation: Event ID 4688 with populated command-line context verified for certutil decoding on `LAB-WIN01`.

## Verified process-creation path

```text
Windows process creation
→ Windows Security log (Event ID 4688)
→ AMA
→ dcr-windows-security
→ SecurityEvent
→ Sentinel scheduled rule: Suspicious Certutil Decode Process
→ SecurityAlert
→ SecurityIncident
```

The verified scheduled rule is enabled, Medium severity, runs every 5 minutes over a 15-minute lookback, triggers on results greater than 0, and enables incident creation. The [Scenario 5 case study](../incidents/INC-005-suspicious-process-investigation.md) documents the benign local simulation, record-specific parent processes and the limits of the displayed alert/incident linkage. The [evidence inventory](../screenshots/EVIDENCE_INVENTORY.md) maps captures to verified stages.
