# INC-001 — Repeated Failed Windows Logons

## Summary
A Microsoft Sentinel detection identified repeated failed Windows
authentication attempts on the lab endpoint.

The activity was generated intentionally as part of an authorized
SOC detection and incident-response simulation.

## Detection

Detection: Repeated Failed Windows Logons

Data source:
- Windows Security Event Log
- Event ID 4625
- Microsoft Sentinel SecurityEvent table

Detection logic:
- Detect 5 or more failed authentication attempts within 15 minutes.

During validation, 9 failed logon events were observed within the
detection window.

## Investigation

Windows Security Event ID 4625 was reviewed in Microsoft Sentinel.

The events originated from the LAB-WIN01 lab endpoint and represented
repeated unsuccessful authentication attempts.

KQL was used to aggregate the failed authentication events by account,
computer, and source IP address.

The telemetry path was validated as:

LAB-WIN01
-> Windows Security Log
-> Azure Monitor Agent
-> Data Collection Rule
-> Log Analytics Workspace
-> Microsoft Sentinel

Historical Sentinel alert records were also available for the repeated
failed-logon detection.

## MITRE ATT&CK

Tactic: Credential Access

Technique:
T1110 — Brute Force

Sub-technique:
T1110.001 — Password Guessing

## Classification

True Positive — Benign / Authorized Simulation

The detection correctly identified intentionally generated failed
authentication activity. No malicious activity was present.

## Response

No containment was required because the activity was generated within
an isolated lab environment.

In a production environment, response actions could include:

- Validate whether the source and account activity are legitimate.
- Review successful logons surrounding the failed attempts.
- Investigate the source IP and affected account.
- Reset or disable a compromised account when appropriate.
- Block malicious sources where appropriate.
- Review related authentication activity for additional indicators.

## Conclusion

The exercise demonstrated the ability to collect Windows security
telemetry, analyze authentication activity with KQL, create a Microsoft
Sentinel detection, and investigate repeated failed-logon activity.
