# 03 — Alert (what Wazuh fired)

## Expected Wazuh alerts

| # | Wazuh rule ID | Rule name | Level | Windows Event | Notes |
|---|---|---|---|---|---|
| 1 | **18106** | Windows: Logon failure. | 5 | **4625** | Fires on *every* failed logon. Filter Security Events by `rule.id:18106` |
| 2 | (correlation rule, note the ID from your dashboard) | Multiple Windows authentication failures / brute force | 10–12 | burst of 4625 | Frequency-based: e.g. 6+ failures in 120s from same source. Record the actual rule ID/level you see. |
| 3 | (account lockout rule) | Account locked out | 8–10 | **4740** | Only if you set `net accounts /lockoutthreshold:5`. Filter `rule.id` for the lockout rule. |
| 4 | (successful logon rule) | Windows: Logon success. | 3 | **4624** | The final success after the burst — `Logon Type 3` (network/SMB). |

> Built-in rule IDs can vary slightly by Wazuh version. **Always record the actual rule ID, name, and level from your dashboard** — that's what a portfolio reviewer checks.

## Where to see them

1. **Wazuh Dashboard → ☰ → Security Events**
   - Filter: `agent.name:winhome01` and `rule.id:(18106 OR <correlation-id>)`
   - Set time window to the attack period.
2. Click any alert → expand the full JSON. Key fields:
   - `data.win.system.eventID`: 4625
   - `data.win.eventdata.ipAddress`: `192.168.100.107` (the attacker)
   - `data.win.eventdata.targetUserName`: jdoe / mreyes / adminlab
   - `data.win.eventdata.logonType`: `3` (network logon — SMB)
   - `data.win.eventdata.status` / `subStatus`: `0xC000006D` / `0xC000006A` (wrong password) or `0xC0000064` (unknown user)

📸 **Screenshots:**
- `evidence/07-wazuh-security-events-alerts.png` — Security Events list showing the burst of 18106 alerts + the higher-level brute-force alert.
- `evidence/08-wazuh-alert-expanded-json.png` — one 4625 alert fully expanded, showing attacker IP, target user, logon type 3, substatus.
- `evidence/09-wazuh-account-lockout-4740.png` — the 4740 lockout alert (if lockout policy enabled).
- `evidence/10-wazuh-successful-logon-4624.png` — the 4624 success right after the burst (adminlab, logon type 3).

## Alert sample (what to quote in your write-up)

```
Rule: 18106 — Windows: Logon failure.
Agent: winhome01 (192.168.100.108)
Event ID: 4625 — An account failed to log on.
Source Network Address: 192.168.100.107
Target User: adminlab
Logon Type: 3 (Network)
Sub Status: 0xC000006A (incorrect password)
```
