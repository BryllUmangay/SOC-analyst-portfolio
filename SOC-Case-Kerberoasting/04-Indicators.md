# 04 — Indicators (IOCs, actual)

## Network / identity IOCs

| Indicator | Value |
|---|---|
| Attacker IP (observed) | `192.168.100.107` (Kali, DHCP — ports 33908/33910) |
| Requesting user | `jdoe@BRYLL.LOCAL` (SID `S-1-5-21-1845810679-4027539410-2363447484-1601`) |
| Target service account | `svc_sql` (SID `...-1602`), password `Password123` (cracked) |
| SPN | `MSSQLSvc/DC01.bryll.local:1433` (host label `DC01`; real DC = `WIN-BPME02TD5L2`) |
| Domain | BRYLL.LOCAL |
| Captured hash | `$krb5tgs$23$*svc_sql$BRYLL.LOCAL$mssqlsvc/dc01.bryll.local$*$a0aa7268e913491e5fbe260edced7ae$d0cfa43f8ff53f7768362f022f2b69698cd629ec4b0930e56699051ab08bbd44c5031a2d603cc844$21715a924239c553be03f5...` (etype 23 RC4) |
| Cracked password | **Password123** (hashcat mode 13100, rockyou, 36864 guesses) |
| logonGuid | `{5D383B63-3681-0783-D26B-9B403DDB62D3}` (ties 4768↔4769) |

## Event IDs observed

| Event ID | Meaning | Key field |
|---|---|---|
| **4769** | TGS requested | `ticketEncryptionType: 0x17` (RC4), serviceName svc_sql, client .107 |
| **4768** | TGT requested (AS-REQ) | jdoe → krbtgt, preAuthType 2, client .107 |

## ATT&CK mapping

- T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting (primary)
- T1003 — OS Credential Dumping (offline hash crack)
- T1558 — Steal or Forge Kerberos Tickets

## SIEM queries (DQL, verified)

```
data.win.system.eventID: 4769 and data.win.eventdata.ticketEncryptionType: "0x17"
data.win.system.eventID: 4768 and data.win.eventdata.targetUserName: "jdoe"
data.win.eventdata.ipAddress: "*192.168.100.107" and data.win.system.eventID in (4768, 4769)
```

## Behavioral signature

Single client IP (`.107`) → 4768 (TGT, jdoe) → within seconds 4769 (TGS for `svc_sql`) with **RC4 0x17** → hashcat mode 13100 cracks to weak password. Many 4769s (multiple SPNs) from one client in a short window = automated kerberoasting (Rubeus/Impacket). RC4 + external/unmanaged client = high confidence.
