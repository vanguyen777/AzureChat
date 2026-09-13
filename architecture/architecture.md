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

- Windows Security: 4625, 4720, 4732, 4733, 4725
- PowerShell Script Block Logging: 4104
- Cross-table temporal correlation: `SecurityEvent` + `Event`
- SID-based correlation: account creation `TargetSid` → privileged group membership `MemberSid`
- Process creation Event ID 4688 remains a planned fifth-scenario validation item.
