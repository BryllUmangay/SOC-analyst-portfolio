# 05 — Investigation (triage steps in Wazuh)

## Step-by-step triage (as the SOC analyst)

### 1. Acknowledge the alert
- Wazuh Dashboard → Security Events → filter `rule.id:18106` (or the brute-force correlation rule).
- Confirm it's not a single typo: count the events in a 5-minute window. Dozens = brute force.

### 2. Identify the source
- Expand one 4625 alert → `data.win.eventdata.ipAddress` = `192.168.100.107`.
- Is this IP a known admin jump-box? No → suspicious.
- 📸 `evidence/08-wazuh-alert-expanded-json.png`

### 3. Check if the attack succeeded (critical!)
- Filter Security Events for `rule.id:<4624-success-rule>` AND `agent.name:winhome01` in the same time window.
- Look for a 4624 (logon type 3) from `192.168.100.107` as `adminlab` right after the failures.
- **If yes → escalation to Critical** (compromised admin). 📸 `evidence/10-wazuh-successful-logon-4624.png`

### 4. Hunt in the archives (raw events, not just alerts)
- ☰ → Explore → Discover → switch index pattern to **`wazuh-archives-*`**.
- Query: `data.win.system.eventID:4625 AND data.win.eventdata.ipAddress:"192.168.100.107"`
- This shows *every* failed attempt, including ones that may have been below alert threshold — count the total, list targeted usernames.
- 📸 `evidence/11-wazuh-archives-4625-burst.png` — archives view with the full burst.

### 5. Check the Windows side (corroborate)
- On winhome01: `eventvwr.msc` → Windows Logs → Security → Filter Current Log → Event ID `4625,4740,4624`.
- Confirm the source IP and timestamps match Wazuh.
- 📸 `evidence/12-windows-eventviewer-4625.png`

### 6. Check for account lockout
- Filter for Event ID `4740` — which accounts locked? (`jdoe`, `mreyes` likely).
- 📸 `evidence/09-wazuh-account-lockout-4740.png` (if applicable)

### 7. Contain
- Rotate `adminlab` password immediately.
- Block `192.168.100.107` at the firewall (lab: note it; in prod: block).
- Review what `adminlab` accessed after the success (shares, files) — search archives for 4663/5140 events.

## Evidence / screenshot checklist (save into `evidence/`)

| Filename | Content |
|---|---|
| `01-kali-nmap-scan.png` | nmap showing 445 open |
| `02-kali-smb-enum.png` | netexec/smbclient enumeration |
| `03-kali-hydra-brute-force.png` | hydra output + success line |
| `04-kali-netexec-brute-force.png` | netexec failures + (Pwn3d!) |
| `05-kali-successful-access.png` | share listing as adminlab |
| `06-kali-metasploit-smb-login.png` | (optional) msf smb_login |
| `07-wazuh-security-events-alerts.png` | Security Events burst of 18106 + correlation rule |
| `08-wazuh-alert-expanded-json.png` | expanded 4625 alert JSON |
| `09-wazuh-account-lockout-4740.png` | 4740 lockout alert (if enabled) |
| `10-wazuh-successful-logon-4624.png` | 4624 success after burst |
| `11-wazuh-archives-4625-burst.png` | Discover/archives showing all raw 4625 |
| `12-windows-eventviewer-4625.png` | Event Viewer Security log filtered |
| `13-custom-wazuh-rule.png` | your custom rule (see 09-Remediation) |
| `14-remediation-lockout-policy.png` | `net accounts` after hardening |
