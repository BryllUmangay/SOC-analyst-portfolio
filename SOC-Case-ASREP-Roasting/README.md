# SOC Case — AS-REP Roasting (Week 2, Case 2)
**Week:** 2 — Active Directory Attacks
**Lab:** Attacker (Kali `butch`, observed IP `192.168.100.107`) → Domain `BRYLL.LOCAL`, DC `192.168.100.105` (hostname `WIN-BPME02TD5L2`, Wazuh agent **`Windows-server`**, agent.id 003), detected by Wazuh SIEM (`192.168.100.102`)
**ATT&CK:** T1558.004 (Steal or Forge Kerberos Tickets: AS-REP Roasting) + T1110.002 (Password Cracking) — Credential Access
**Severity:** **High** — offline-crackable credential harvested with zero logon failures; silent by default; any account with `DONT_REQUIRE_PREAUTH` is vulnerable
**Status:** ✅ Completed (2026-11-04)

## Case Structure
| File | Contents |
|---|---|
| `01-Scenario.md` | Background, vulnerable account setup (`DONT_REQUIRE_PREAUTH`) |
| `02-Attack-Simulation.md` | Kali step-by-step (time sync → enum/roast → crack) |
| `03-Alert.md` | Events detected: 4768 with **preAuthType=0** (smoking gun) + RC4 0x17 |
| `04-Indicators.md` | IOCs: account, UAC flag, hash format, client IP, event fields |
| `05-Investigation.md` | Triage in Wazuh + evidence list (exact filenames) |
| `06-Timeline.md` | Real event timeline |
| `07-Analysis.md` | Why preAuthType=0 is the smoking gun, vs Kerberoasting, detection gaps |
| `08-Conclusion.md` | Findings, severity, lessons |
| `09-Remediation.md` | Hardening (remove pre-auth exemption, AES, long passwords) + Wazuh rule |
| `evidence/` | 6 screenshots (filenames listed below) |
| `kali-commands.txt` | Exact commands run |

## Evidence screenshots (exact filenames — place in `evidence/`)
| Filename | Content |
|---|---|
| `00-kali-time-sync.png` | `ntpdate 192.168.100.105` — clock stepped by **-180.107310s** (Kali ~3 min fast) |
| `01-dc-asrep-user-created.png` | DC PowerShell: `New-ADUser svc_file` (Password123) + `Set-ADAccountControl -DoesNotRequirePreAuth $true`; UAC **4260352 (0x410200)**, SID `...-1603` |
| `02-kali-getnpusers-roast.png` | `GetNPUsers.py -request -format hashcat` → `$krb5asrep$23$svc_file@BRYLL.LOCAL:...` hash saved to `asrep_hashes.txt` |
| `03-kali-hashcat-cracked.png` | hashcat mode **18200**, rockyou.txt → Status **Cracked**, Recovered 1/1 → **Password123** (325 kH/s, 36864 guesses, ~39 s) |
| `04-wazuh-4768-list.png` | Wazuh Discover — `data.win.system.eventID: 4768`, agent `Windows-server`, **20 hits**; malicious row: `svc_file`, `ticketOptions 0x50800000`, client `::ffff:192.168.100.107:34658` |
| `05-wazuh-4768-expanded-preauth0.png` | Expanded 4768 (eventRecordID **8654**) — **`preAuthType: 0`** (no pre-auth — smoking gun), `ticketEncryptionType: 0x17` (RC4), `targetUserName: svc_file`, `serviceName: krbtgt` |

## Result Summary (actual, from evidence)
- **Vulnerable (roasted) account:** `svc_file` (SID `S-1-5-21-1845810679-4027539410-2363447484-1603`, ObjectGUID `c57a3e1c-13a0-478a-855e-3b799b04fa15`). UserAccountControl **4260352 = 0x410200** = `DONT_REQUIRE_PREAUTH` (0x400000) + `DONT_EXPIRE_PASSWORD` (0x10000) + `NORMAL_ACCOUNT` (0x200). PasswordNeverExpires, LastLogon `<never>`, PasswordLastSet `2026-11-04 09:37:10`.
- **Low-priv domain user used by tool:** `jdoe@BRYLL.LOCAL` / `P@ssw0rd` (used by GetNPUsers for LDAP binding/enumeration).
- **Hash captured:** `$krb5asrep$23$svc_file@BRYLL.LOCAL:ed31b62c081173a76b40353846dbae46$...a130baccaa6971571` — `$23$` = RC4-HMAC (etype 23), crackable offline (hashcat mode 18200). Full hash visible in `evidence/02-kali-getnpusers-roast.png`.
- **Cracked:** hashcat mode 18200, `/usr/share/wordlists/rockyou.txt`, Status **Cracked**, Recovered 1/1 (325.0 kH/s, 36864/14344385 guesses = 0.26%, ~39 s) → plaintext **`Password123`**.
- **Detection (Wazuh, agent `Windows-server` = DC):**
  - **Event ID 4768** (TGT requested) — `targetUserName: svc_file`, `serviceName: krbtgt`, **`preAuthType: 0`** (no pre-authentication — smoking gun; normal = 2), **`ticketEncryptionType: 0x17`** (RC4), `ipAddress: ::ffff:192.168.100.107`, `ipPort: 34658`, `status: 0x0`, `ticketOptions: 0x50800000`, eventRecordID **8654**, computer `WIN-BPME02TD5L2.bryll.local`.
  - **Correlation:** `targetSid` ends **-1603** → matches `svc_file`'s AD SID exactly (from `01-dc-asrep-user-created.png`). UAC `0x410200` in GetNPUsers output includes `0x400000` = DONT_REQUIRE_PREAUTH.
  - Baseline comparison: normal 4768 from domain-joined `DESKTOP-B5RJ6HF6` (Win10 Pro) uses `ticketOptions 0x40810010` with pre-auth — only the `svc_file` event has preAuthType=0.
- **Finding:** Kali & DC clocks on EST (UTC-5); Wazuh dashboard renders in browser local time (PHT, UTC+8) → **13 h display offset** (Kali 09:44 EST = Wazuh 22:44 PHT). Kali was ~3 min fast pre-sync (ntpdate stepped -180 s) — inside the 5-min Kerberos tolerance but close.
