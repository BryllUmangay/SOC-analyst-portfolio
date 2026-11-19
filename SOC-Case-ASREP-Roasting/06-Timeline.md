# 06 — Timeline (actual, from evidence)
**Timezone note:** Kali + DC on EST (UTC-5); Wazuh dashboard renders in browser local time (PHT, UTC+8) → **13 h display offset**. Kali 09:44 EST = Wazuh 22:44 PHT = 14:44 UTC. Times below show both.

| # | EST (Kali/DC) | PHT (Wazuh dash) | Event | Source | Evidence |
|---|---|---|---|---|---|
| 1 | ~09:35 | 22:35 | Baseline: normal 4768 TGT from `DESKTOP-B5RJ6HF6$` (ticketOptions 0x40810010, pre-auth) | DC→Wazuh | `04-wazuh-4768-list.png` |
| 2 | 09:37:10 | 22:37:10 | `svc_file` created, `PasswordLastSet = 2026-11-04 09:37:10.791566`; `DONT_REQUIRE_PREAUTH` set (UAC 0x410200) | DC | `01-dc-asrep-user-created.png`, `02-kali-getnpusers-roast.png` |
| 3 | 09:42:05 | 22:42:05 | Kali: stop timesyncd, `ntpdate 192.168.100.105` → clock stepped **-180.107310 s** (was ~3 min fast) | Kali | `00-kali-time-sync.png` |
| 4 | ~09:44 | 22:44 | `GetNPUsers.py ... -request` → AS-REP hash `$krb5asrep$23$svc_file@BRYLL.LOCAL:...` captured to `asrep_hashes.txt` | Kali | `02-kali-getnpusers-roast.png` |
| 5 | 09:44:37 → 09:45:16 | 22:44:37 → 22:45:16 | hashcat mode 18200 (rockyou.txt) → Status **Cracked**, Recovered 1/1 → **Password123** (325 kH/s, 36864 guesses, ~39 s) | Kali | `03-kali-hashcat-cracked.png` |
| 6 | 09:45:51 | **22:45:51.368** | **4768** — `svc_file` TGT requested, **preAuthType=0**, RC4 0x17, client `::ffff:192.168.100.107:34658`, eventRecordID **8654** (captured in Wazuh archives) | DC→Wazuh | `04-wazuh-4768-list.png`, `05-wazuh-4768-expanded-preauth0.png` |
| 7 | containment | — | Reset `svc_file`, clear `DONT_REQUIRE_PREAUTH`, hunt preAuthType=0 across domain | DC/Wazuh | — |

Note: the expanded 4768 (record 8654, 09:45:51 EST) falls just after hashcat stopped — consistent with a second `GetNPUsers` re-request / verification run; multiple roast attempts are reflected in the 20 total 4768 hits.

## Key correlation chain
`ntpdate (fix skew) → New-ADUser + Set-ADAccountControl (UAC 0x410200) → GetNPUsers -request (AS-REQ no pre-auth) → 4768 preAuthType=0 + RC4 0x17 (targetSid -1603 = svc_file) → $krb5asrep$23$ hash → hashcat 18200 cracks Password123`.
