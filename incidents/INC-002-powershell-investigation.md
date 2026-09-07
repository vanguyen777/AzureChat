# INC-002 — Suspicious PowerShell Base64 Decoding

## Summary

Microsoft Sentinel detected PowerShell script activity containing
Base64-decoding functionality on LAB-WIN01.

The activity was intentionally generated as part of an authorized
SOC detection and incident-response lab.

## Detection

Detection:
Suspicious PowerShell Base64 Decoding

Data source:
- PowerShell Script Block Logging
- Event ID 4104
- Microsoft-Windows-PowerShell/Operational
- Log Analytics Event table

Detection logic:
- Identify PowerShell script blocks containing `FromBase64String`.

Example KQL:

Event
| where EventID == 4104
| where RenderedDescription contains "FromBase64String"
| project TimeGenerated, Computer, UserName, RenderedDescription

## Investigation

PowerShell Script Block Logging recorded the executed script content
as Event ID 4104.

KQL analysis identified script blocks containing
`FromBase64String`, indicating that Base64 data was being decoded
through PowerShell.

The activity was traced to LAB-WIN01 and matched the controlled
simulation performed during the lab.

The telemetry path was validated as:

LAB-WIN01
-> PowerShell Operational Log
-> Event ID 4104
-> Azure Monitor Agent
-> dcr-powershell-logs
-> Log Analytics Event table
-> Microsoft Sentinel analytics rule
-> SecurityAlert
-> SecurityIncident

A fresh Microsoft Sentinel alert and corresponding incident were
successfully generated.

## MITRE ATT&CK

Tactic:
Execution

Technique:
T1059 — Command and Scripting Interpreter

Sub-technique:
T1059.001 — PowerShell

## Classification

True Positive — Benign / Authorized Simulation

The detection correctly identified the intentionally generated
PowerShell activity. No malicious compromise occurred.

## Response

No containment was required because the activity was generated
within an authorized lab environment.

In a production environment, investigation could include:

- Review the complete PowerShell script block.
- Identify the account that executed the script.
- Examine related process and authentication activity.
- Decode suspicious encoded content in a safe analysis environment.
- Search for similar PowerShell activity across other endpoints.
- Determine whether the activity was authorized.
- Isolate the endpoint if malicious activity is confirmed.

## Conclusion

The exercise demonstrated configuration and collection of PowerShell
Script Block Logging, KQL-based threat detection, creation of a
scheduled Microsoft Sentinel analytics rule, and validation through
a generated Sentinel alert and incident.
