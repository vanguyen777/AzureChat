# INC-003 — Failed Logons Followed by Suspicious PowerShell Activity

## Summary

Microsoft Sentinel detected a sequence of failed Windows authentication
attempts followed by suspicious PowerShell activity on LAB-WIN01.

The activity was intentionally generated as part of an authorized SOC
detection and incident-response lab.

The detection correlated Windows Security Event ID 4625 with PowerShell
Script Block Logging Event ID 4104 on the same endpoint.

## Detection

Rule:
Multi-Stage Failed Logons Followed by PowerShell

Severity:
High

Rule frequency:
5 minutes

Rule lookback:
30 minutes

Correlation window:
15 minutes

Trigger:
Query results greater than 0

Incident creation:
Enabled

### Authentication telemetry

Table:
SecurityEvent

Event ID:
4625 — Failed logon

### PowerShell telemetry

Table:
Event

Event ID:
4104 — PowerShell Script Block Logging

Suspicious indicator:
FromBase64String

## Correlation Logic

The detection searches for failed Windows authentication activity and
joins those events with PowerShell Script Block Logging events from the
same computer.

A match is generated when PowerShell activity containing
`FromBase64String` occurs after a failed authentication event and within
15 minutes of that event.

The correlation uses the Computer field to associate activity from the
two telemetry sources.

Telemetry path:

Windows Security Log
-> Event ID 4625
-> AMA
-> SecurityEvent

PowerShell Operational Log
-> Event ID 4104
-> AMA
-> dcr-powershell-logs
-> Event

SecurityEvent + Event
-> KQL correlation
-> Sentinel scheduled analytics rule
-> SecurityAlert
-> SecurityIncident

## Investigation

Multiple failed authentication attempts were intentionally generated on
LAB-WIN01 using an invalid account.

PowerShell activity was subsequently generated on the same endpoint.

PowerShell Script Block Logging captured the activity as Event ID 4104.
The script contained `[Convert]::FromBase64String`, which matched the
PowerShell component of the correlation rule.

KQL analysis correlated the Windows authentication and PowerShell
telemetry based on the endpoint and event timestamps.

The Microsoft Sentinel scheduled analytics rule generated a fresh
SecurityAlert.

Incident creation was enabled for the analytics rule and a fresh
SecurityIncident was successfully generated from subsequent matching
activity.

The activity was confirmed to be part of the authorized SOC lab
simulation.

## MITRE ATT&CK

### Credential Access

T1110 — Brute Force

T1110.001 — Password Guessing

### Execution

T1059 — Command and Scripting Interpreter

T1059.001 — PowerShell

## Classification

True Positive — Benign / Authorized Simulation

The detection correctly identified the simulated activity. No
unauthorized compromise occurred.

## Response

No containment was required because the activity was generated within
an authorized lab environment.

In a production environment, investigation could include:

- Identify the account associated with the failed authentication attempts.
- Determine the source of the authentication failures.
- Review successful authentication events around the same period.
- Review PowerShell Script Block Logging for the complete executed script.
- Examine related process creation telemetry.
- Investigate network connections and downloaded content.
- Search for similar activity across other endpoints.
- Review endpoint security alerts.
- Determine whether the PowerShell execution was authorized.
- Isolate the endpoint and remediate affected accounts if compromise is confirmed.

## Conclusion

This investigation demonstrated multi-source detection engineering in
Microsoft Sentinel by correlating Windows authentication telemetry with
PowerShell Script Block Logging.

The lab validated the complete detection workflow:

Telemetry collection
-> Cross-table KQL correlation
-> Scheduled analytics rule
-> Security alert
-> Sentinel incident
-> Investigation
-> MITRE ATT&CK mapping
