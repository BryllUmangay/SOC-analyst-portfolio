# 04 — Indicators of Compromise (IOCs)
## Account indicators (AD)
| Indicator | Value |
|---|---|
| Roasted account | `svc_file` (SamAccountName), DN `CN=svc_file,CN=Users,DC=bryll,DC=local` |
| Account SID | `S-1-5-21-1845810679-4027539410-2363447484-1603` (RID 1603) |
| ObjectGUID | `c57a3e1c-13a0-478a-855e-3b799b04fa15` |
| UserAccountControl | **4260352 (0x410200)** — includes `DONT_REQUIRE_PREAUTH` (0x400000) |
| Cracked password | **`Password123`** (weak, in rockyou.txt top 0.26%) |
| PasswordLastSet | `2026-11-04 09:37:10.791566`; LastLogon `<never>` (fresh account, never used interactively) |
| Low-priv pivot account | `jdoe@BRYLL.LOCAL` (used by GetNPUsers for LDAP bind) |

## Network / host indicators
| Indicator | Value |
|---|---|
| Attacker source IP | **`192.168.100.107`** (Kali, observed; DHCP-assigned), source port **34658** |
| Attacker tool | Impacket `GetNPUsers.py` v0.13.1 (`-request -format hashcat`) |
| Target | DC `192.168.100.105` / `WIN-BPME02TD5L2.bryll.local`, TCP 88 (Kerberos) |
| Crack tool | hashcat mode **18200**, wordlist `/usr/share/wordlists/rockyou.txt`, 325 kH/s |

## Credential indicator (captured hash)
Format: `$krb5asrep$23$svc_file@BRYLL.LOCAL:<salt>$<cipher>`
- Prefix (actual): `$krb5asrep$23$svc_file@BRYLL.LOCAL:ed31b62c081173a76b40353846dbae46$d215bc171f2279e2...`
- Tail (actual): `...e10a51142f3a24e751da3e92417640abea130baccaa6971571`
- `$23$` = etype 23 (RC4-HMAC) — offline-crackable. Full hash preserved in `evidence/02-kali-getnpusers-roast.png` and `evidence/03-kali-hashcat-cracked.png`.

## SIEM / log indicators (Wazuh DQL)
| Query | What it finds |
|---|---|
| `data.win.system.eventID: 4768 and data.win.eventdata.preAuthType: "0"` | **AS-REP roast in progress** (highest fidelity) |
| `data.win.system.eventID: 4768 and data.win.eventdata.ticketEncryptionType: "0x17"` | RC4 TGTs (roastable) — correlate with preAuthType |
| `data.win.system.eventID: 4768 and data.win.eventdata.targetUserName: "svc_file"` | All TGT requests for the roasted account |
| `data.win.system.eventID: 4768` | Baseline — 20 hits/24 h; only `svc_file` row has preAuthType=0 |

## Event fields (the smoking-gun tuple)
`eventID=4768` + `preAuthType=0` + `ticketEncryptionType=0x17` + `targetUserName=<user-account>` + `ipAddress=<unmanaged>` → AS-REP Roasting (T1558.004).

## MITRE
- **T1558.004** — Steal or Forge Kerberos Tickets: AS-REP Roasting
- **T1110.002** — Brute Force: Password Cracking (offline hashcat phase)
