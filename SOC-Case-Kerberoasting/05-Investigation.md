# 05 — Investigation (triage steps, actual)

1. **Time sync required:** DC clock ~3 days behind real date; stopped `systemd-timesyncd`, `ntpdate 192.168.100.105` → Kali stepped Nov 3 → Oct 31. (First roast failed: `KRB_AP_ERR_SKEW`.) 📸 `evidence/00-kali-time-sync.png`
2. **Pre-flight on DC:** audit policy Kerberos Service Ticket Operations = Success; `jdoe` + `svc_sql` created; SPN `MSSQLSvc/DC01.bryll.local:1433` registered (confirmed by `setspn -L svc_sql`). 📸 `evidence/00-preflight-check*.png`
3. **Enum:** `GetUserSPNs.py` (Impacket v0.13.1) → `svc_sql` SPN. 📸 `evidence/01-kali-getuserspns-enum.png`
4. **Roast:** `-request` → `$krb5tgs$23$...` hash (RC4 etype 23) saved. 📸 `evidence/02-kali-kerberoast-hash.png`
5. **Crack:** hashcat mode 13100 → Status Cracked, Recovered 1/1 → `Password123`. 📸 `evidence/03-kali-hashcat-cracked.png`
6. **Wazuh 4769 found:** `data.win.system.eventID: 4769`, agent `Windows-server` → **33 hits**. 📸 `evidence/4-wazuh-4769-list.png` (note: filename single digit `4-`)
7. **4769 expanded:** `ticketEncryptionType: 0x17` (RC4), `serviceName: svc_sql`, `targetUserName: jdoe@BRYLL.LOCAL`, `ipAddress: ::ffff:192.168.100.107`, eventRecordID 7568. 📸 `evidence/05-wazuh-4769-expanded-rc4.png`, `05-wazuh-4769-expanded-rc4-.2.png`
8. **4768 correlated:** jdoe TGT → krbtgt, same client IP .107, eventRecordID 7567 (consecutive), same logonGuid. 📸 `evidence/06-wazuh-4768-tgt.png`
9. **Containment:** reset `svc_sql` password to 25+ chars, set AES-only (msDS-SupportedEncryptionTypes = 24), rotate `jdoe`, hunt for other 4769 RC4 requests from .107.

## Evidence folder (11 screenshots — exact filenames)

| Filename | Content |
|---|---|
| `00-kali-time-sync.png` | ntpdate step (Nov 3 → Oct 31) |
| `00-preflight-check.png` / `1` / `2` | DC audit policy + accounts + SPN |
| `01-kali-getuserspns-enum.png` | GetUserSPNs enum (svc_sql) |
| `02-kali-kerberoast-hash.png` | Full $krb5tgs$23$ hash |
| `03-kali-hashcat-cracked.png` | hashcat Cracked → Password123 |
| `4-wazuh-4769-list.png` | Wazuh 4769 list (33 hits, agent Windows-server) |
| `05-wazuh-4769-expanded-rc4.png` / `-.2.png` | Expanded 4769 (RC4 0x17, client .107, svc_sql, jdoe) |
| `06-wazuh-4768-tgt.png` | Expanded 4768 (jdoe TGT, record 7567) |

## Analyst note

The **consecutive eventRecordIDs (7567 → 7568)** and matching `logonGuid` prove the TGT and TGS are the same session — the cleanest possible correlation. The attacker IP is `.107` this run (DHCP, not the `.106` seen in Week 1) — always use the observed IP from the event, not the assumed one. The SPN host label `DC01` does not match the real DC hostname `WIN-BPME02TD5L2` — kerberoasting works on any registered SPN regardless, which is why SPN inventory matters.
