# SOC Case — Kerberoasting (Week 2, Case 1)

**Week:** 2 — Active Directory Attacks
**Lab:** Attacker (Kali, observed IP `192.168.100.107`) → Domain `BRYLL.LOCAL`, DC `192.168.100.105` (hostname `WIN-BPME02TD5L2`, Wazuh agent **`Windows-server`**, agent.id 003), detected by Wazuh SIEM (`192.168.100.102`)
**ATT&CK:** T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting) — Credential Access
**Severity:** **High** — offline crackable service-account hash; no interactive logon required; silent by default
**Status:** ✅ Completed (2026-10-31 lab time / 2026-11-04 real time)

## Case Structure

| File | Contents |
|---|---|
| `01-Scenario.md` | Background, AD setup, SPN account |
| `02-Attack-Simulation.md` | Kali step-by-step (time sync → enum → roast → crack) |
| `03-Alert.md` | Events detected: 4769 (RC4 0x17), 4768 (TGT) |
| `04-Indicators.md` | IOCs: SPN, hash, client IP, encryption type, event IDs |
| `05-Investigation.md` | Triage in Wazuh + evidence list (exact filenames) |
| `06-Timeline.md` | Real event timeline |
| `07-Analysis.md` | Why RC4 is the smoking gun, detection gaps, mitigation |
| `08-Conclusion.md` | Findings, severity, lessons |
| `09-Remediation.md` | Hardening (AES-only service accounts, long passwords) + Wazuh rule |
| `evidence/` | 11 screenshots (filenames listed below) |
| `kali-commands.txt` | Exact commands run |

## Evidence screenshots (exact filenames — place in `evidence/`)

| Filename | Content |
|---|---|
| `00-kali-time-sync.png` | `ntpdate` stepped Kali from Nov 3 → Oct 31 to match DC clock |
| `00-preflight-check.png` / `00-preflight-check1.png` / `00-preflight-check2.png` | DC audit policy + account + SPN registration (`setspn -L svc_sql`) |
| `01-kali-getuserspns-enum.png` | `GetUserSPNs.py` enum — `svc_sql` SPN `MSSQLSvc/DC01.bryll.local:1433` |
| `02-kali-kerberoast-hash.png` | `-request` output — full `$krb5tgs$23$*svc_sql$BRYLL.LOCAL$...` hash (RC4 etype 23) |
| `03-kali-hashcat-cracked.png` | hashcat mode 13100 — Status **Cracked**, Recovered 1/1 → `Password123` |
| `4-wazuh-4769-list.png` | Wazuh Discover — `data.win.system.eventID: 4769`, agent `Windows-server`, **33 hits** |
| `05-wazuh-4769-expanded-rc4.png` / `05-wazuh-4769-expanded-rc4-.2.png` | Expanded 4769 — `ticketEncryptionType: 0x17` (RC4), client `::ffff:192.168.100.107`, `serviceName: svc_sql`, `targetUserName: jdoe@BRYLL.LOCAL` |
| `06-wazuh-4768-tgt.png` | Expanded 4768 — jdoe TGT request, eventRecordID 7567 (consecutive with 4769's 7568) |

## Result Summary (actual, from evidence)

- **Compromised domain user:** `jdoe@BRYLL.LOCAL` (SID `S-1-5-21-1845810679-4027539410-2363447484-1601`), password `P@ssw0rd`. Any valid domain user can roast — no admin needed.
- **Roasted service account:** `svc_sql` (SID `...-1602`), SPN `MSSQLSvc/DC01.bryll.local:1433`, password `Password123` (weak → cracked).
- **Hash captured:** `$krb5tgs$23$*svc_sql$BRYLL.LOCAL$mssqlsvc/dc01.bryll.local$*$...` — `$23$` = RC4-HMAC (etype 23), crackable offline.
- **Cracked:** hashcat mode 13100, rockyou.txt, Status **Cracked**, Recovered 1/1 (36864 guesses, ~1 sec) → `Password123`.
- **Detection (Wazuh, agent `Windows-server`):**
  - **Event ID 4769** (Kerberos TGS requested) — `serviceName: svc_sql`, **`ticketEncryptionType: 0x17` (RC4 — smoking gun)**, `targetUserName: jdoe@BRYLL.LOCAL`, `ipAddress: ::ffff:192.168.100.107`, port 33910, status 0x0, eventRecordID 7568, logonGuid `{5D383B63-3681-0783-D26B-9B403DDB62D3}`.
  - **Event ID 4768** (TGT requested) — jdoe → `krbtgt`, preAuthType 2, ticketEncryptionType 0x17, eventRecordID 7567 (**consecutive with 4769** — perfect correlation).
- **Finding:** DC clock runs ~3 days behind real date (Oct 31 vs Nov 4); Kali required `ntpdate` + stopping `systemd-timesyncd` to avoid `KRB_AP_ERR_SKEW`. First roast attempt failed with clock skew — documented honestly.
- **Finding:** SPN host part `DC01` does not match real DC hostname `WIN-BPME02TD5L2` — irrelevant to kerberoasting (any registered SPN roasts), but noted.
