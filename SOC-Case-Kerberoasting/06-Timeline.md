# 06 — Timeline (actual, from evidence)

Note: DC clock runs ~3 days behind real date (Oct 31 lab time vs Nov 4 real). Kali required ntpdate to match. Times below = DC/lab time (Oct 31, 2026).

| # | Time | Event | Source | Evidence filename |
|---|---|---|---|---|
| 1 | pre-attack | DC config: audit policy Success, jdoe + svc_sql created, SPN `MSSQLSvc/DC01.bryll.local:1433` registered | DC | `00-preflight-check*.png` |
| 2 | Oct 31 ~17:07 | Kali: stop timesyncd, `ntpdate 192.168.100.105` → clock stepped Nov 3 → Oct 31 (earlier roast failed: `KRB_AP_ERR_SKEW`) | Kali | `00-kali-time-sync.png` |
| 3 | Oct 31 ~17:10 | `GetUserSPNs.py` enum → svc_sql SPN (LDAP only) | Kali | `01-kali-getuserspns-enum.png` |
| 4 | Oct 31 17:18:17 | **4768** — jdoe TGT requested (AS-REQ), client .107:33908, RC4 0x17, eventRecordID **7567** | DC → Wazuh | `06-wazuh-4768-tgt.png` |
| 5 | Oct 31 17:18:17 | **4769** — jdoe TGS requested for `svc_sql`, **RC4 0x17**, client .107:33910, eventRecordID **7568** (consecutive) | DC → Wazuh | `05-wazuh-4769-expanded-rc4*.png`, `4-wazuh-4769-list.png` |
| 6 | Oct 31 17:18:17 | TGS-REP hash captured: `$krb5tgs$23$*svc_sql$BRYLL.LOCAL$...` (RC4 etype 23) | Kali | `02-kali-kerberoast-hash.png` |
| 7 | Oct 31 17:18:17–18 | hashcat mode 13100, rockyou.txt → Status **Cracked**, Recovered 1/1 (36864 guesses, ~1 sec) → **Password123** | Kali | `03-kali-hashcat-cracked.png` |
| 8 | containment | Reset svc_sql (25+ chars, AES-only), rotate jdoe, hunt 4769 RC4 from .107 | DC/Wazuh | — |

## Key correlation chain

`ntpdate (fix skew) → GetUserSPNs enum (LDAP) → 4768 TGT (jdoe, .107, rec 7567) → 4769 TGS (svc_sql, RC4 0x17, .107, rec 7568) → $krb5tgs$23$ hash → hashcat cracks Password123`. Consecutive eventRecordIDs + matching logonGuid tie 4768↔4769 as one session.
