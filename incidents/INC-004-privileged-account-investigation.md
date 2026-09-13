# INC-004 — New Local Account Added to Administrators

## Summary

Microsoft Sentinel detected a newly created local Windows account being added to the local Administrators group on `LAB-WIN01`.

The activity was intentionally generated as part of an authorized SOC detection and incident-response lab. A fresh test account, `soclab-tempadmin2`, was created and then added to the local Administrators group.

## Detection

**Rule:** `Local Account Added to Administrators Group`  
**Severity:** High  
**Rule frequency:** 5 minutes  
**Rule lookback:** 30 minutes  
**Trigger:** Query results greater than 0  
**Incident creation:** Enabled

### Windows telemetry

- Event ID 4720 — A user account was created.
- Event ID 4732 — A member was added to a security-enabled local group.
- Event ID 4733 — A member was removed from a security-enabled local group during cleanup.
- Event ID 4725 — The test account was disabled during cleanup.

## Correlation Logic

The detection identifies newly created local accounts and correlates them with subsequent membership additions to the built-in local Administrators group (`S-1-5-32-544`).

Because Event ID 4732 can record `MemberName` as `-`, the correlation uses the account SID rather than relying on a resolved member name. The SID from the 4720 account-creation event is matched to `MemberSid` from the 4732 group-membership event. The privileged addition must occur after account creation and within 15 minutes.

Telemetry path:

Windows Security Log
-> Event IDs 4720 / 4732
-> Azure Monitor Agent
-> SecurityEvent
-> KQL SID + temporal correlation
-> Sentinel scheduled analytics rule
-> SecurityAlert
-> SecurityIncident

## Investigation

Historical validation showed a controlled account creation sequence on `LAB-WIN01` in which `soclab-tempadmin` was created and then added to `Builtin\\Administrators`. The account SID from Event ID 4720 matched the `MemberSid` in Event ID 4732, demonstrating reliable SID-based correlation even when `MemberName` was unresolved.

A fresh validation sequence was then generated after the analytics rule was active using `soclab-tempadmin2`. Log Analytics confirmed fresh 4720 and 4732 telemetry. The enabled Sentinel analytics rule generated a fresh `SecurityAlert` and corresponding `SecurityIncident`.

After evidence capture, the test account was removed from the Administrators group and disabled. The account was left disabled rather than deleted to preserve a clean lab state and associated lifecycle telemetry.

## MITRE ATT&CK

**Tactic:** Privilege Escalation  
**Technique:** T1098 — Account Manipulation

This reflects the mapping configured on the validated Sentinel analytics rule.

## Classification

**True Positive — Benign / Authorized Simulation**

The detection correctly identified the intentionally generated privileged-account activity. No unauthorized compromise occurred.

## Response

No containment was required beyond lab cleanup because the activity was authorized. In a production environment, investigation should verify who created the account, whether the privileged group membership was authorized, surrounding authentication and process activity, other changes made by the actor, and whether the affected account should be disabled or removed.

## Conclusion

This scenario validated a complete privileged-account monitoring workflow using Windows Security telemetry, SID-based KQL correlation, a scheduled Microsoft Sentinel analytics rule, a fresh security alert, and a fresh Sentinel incident.
