# INC-004 — Local Administrator Group Membership Change

> Status: **Prepared / not yet validated in Sentinel**
>
> This report becomes final only after the controlled simulation is run on `LAB-WIN01` and the resulting Sentinel alert/incident is verified.

## Summary

A controlled SOC lab simulation creates a local test account and adds it to the built-in Windows `Administrators` group on `LAB-WIN01`. The detection focuses on Windows Security Event ID 4732 where the target group SID is `S-1-5-32-544` (built-in Administrators).

## Detection

- Data source: `SecurityEvent`
- Event ID: `4732`
- Target group SID: `S-1-5-32-544`
- Detection file: `detections/local-admin-group-addition.kql`

## Supporting Account Activity

The simulation is also expected to generate Event ID `4720` when the temporary local account is created.

## Investigation Checklist

- Confirm Event ID 4720 for the test account creation.
- Confirm Event ID 4732 for membership addition to the local Administrators group.
- Record `SubjectAccount`, `MemberName`, `MemberSid`, `TargetAccount`, and timestamps.
- Confirm the event was ingested into Log Analytics from `LAB-WIN01`.
- Confirm the scheduled analytics rule returns the expected result.
- Confirm a fresh `SecurityAlert` and `SecurityIncident` are generated.
- Capture screenshots of the KQL result, analytics rule, alert, and incident.

## MITRE ATT&CK

Planned mapping: **Privilege Escalation / Account Manipulation (T1098)**. Final mapping should be confirmed against the exact validated behavior before this report is marked complete.

## Classification

**True Positive — Benign / Authorized Simulation**

The activity is intentionally generated for the SOC lab and should not result in containment.

## Production Response Considerations

In a production environment, an unexpected local administrator addition should prompt validation of the initiating account, the added principal, recent authentication activity, endpoint process activity, change-management context, and whether the host should be isolated or credentials reset.

## Validation Evidence

To be added after live testing.
