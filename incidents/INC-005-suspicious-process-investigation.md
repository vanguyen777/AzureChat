# INC-005 — Suspicious Certutil Decode Process

> Status: **Pending live validation.** This document is a reporting scaffold only. Do not treat any field below as evidence until it is populated from fresh LAB-WIN01, Log Analytics, Microsoft Sentinel, and screenshot results.

## Summary

- Detection rule: Suspicious Certutil Decode Process
- Endpoint: LAB-WIN01
- Classification: Pending
- Simulation: Local benign marker encoded and decoded with certutil.exe

## Preconditions to verify

- [ ] Event ID 4688 is generated on LAB-WIN01.
- [ ] dcr-windows-security sends Event ID 4688 to SecurityEvent.
- [ ] Command-line auditing is enabled and CommandLine is populated.
- [ ] The benign simulation completed without download, code execution, persistence, or security-control bypass.

## Detection

- KQL: [detections/suspicious-process-detection.kql](../detections/suspicious-process-detection.kql)
- Sentinel rule name: Pending
- Severity: Medium (proposed)
- Frequency/lookback: 5 minutes / 15 minutes (proposed)
- MITRE ATT&CK: Defense Evasion; T1140 — Deobfuscate/Decode Files or Information (proposed)

## Evidence to capture

- [ ] Endpoint simulation and harmless output
- [ ] Event ID 4688 in Log Analytics with NewProcessName and CommandLine
- [ ] KQL detection result
- [ ] Sentinel scheduled-rule configuration
- [ ] Rule verification after creation
- [ ] Fresh SecurityAlert showing the tested process/host
- [ ] Fresh SecurityIncident linked to that alert

## Investigation notes

Populate only from verified evidence:

- First observed time:
- Process name:
- Command line:
- Parent process:
- Account/SID:
- Host:
- EventRecordId:
- Alert ID:
- Incident ID:

## Response and disposition

No containment should be performed for this authorized lab simulation. If the same behavior appeared unexpectedly in production, investigate the initiating account, parent process, decoded file, adjacent process/network activity, and authorization context before deciding on containment.

## Conclusion

Pending live validation. The scenario must not be marked complete until telemetry, detection, scheduled rule, alert, incident, and evidence links are all verified.
