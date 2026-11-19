# 05 — Investigation (triage steps, actual)
## Triage workflow
1. **Hunt query** (Wazuh Discover, index `wazuh-archives-*`, DQL):
   `data.win.system.eventID: 4768 and data.win.eventdata.preAuthType: "0"`
   → returns the `svc_file` event (agent `Windows-server`). If no custom alert exists, this is how you find it retroactively.
2. **Expand the event** — record: `targetUserName`, `targetSid`, `ipAddress`/`ipPort`, `preAuthType`, `ticketEncryptionType`, `status`, `eventRecordID`.
   → actual: `svc_file` / `...-1603` / `::ffff:192.168.100.107:34658` / **preAuthType 0** / **0x17 RC4** / status 0x0 / record **8654**.
3. **Correlate SID to AD account** — `targetSid ...-1603` matches `svc_file` (from `Get-ADUser` in setup screenshot). Confirm the account has `DoesNotRequirePreAuth = True`:
   `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth, UserAccountControl`
4. **Baseline the noise** — run `data.win.system.eventID: 4768` (20 hits). Normal events (e.g., `DESKTOP-B5RJ6HF6$`, `ticketOptions 0x40810010`) have preAuthType=2. Only user accounts with the UAC 0x400000 bit produce preAuthType=0.
5. **Check attacker IP** — `192.168.100.107` is an unmanaged Kali host (not a domain asset). A preAuthType=0 request from an unmanaged IP = active roasting.
6. **Post-compromise check** — did the attacker USE `svc_file` after cracking? Hunt:
   - `data.win.system.eventID: 4624 and data.win.eventdata.targetUserName: "svc_file"` (any interactive/network logon)
   - `data.win.system.eventID: 4768 and data.win.eventdata.targetUserName: "svc_file" and not data.win.eventdata.preAuthType: "0"` (normal logons after crack)
   - In this lab: `svc_file` LastLogon `<never>` — cracking was the final step; no follow-on logon observed.
7. **Scope exposure** — enumerate `svc_file` group memberships, ACLs, and share rights to determine blast radius if the credential is valid.

## Evidence list (exact filenames in `evidence/`)
| # | File | Shows |
|---|---|---|
| 1 | `00-kali-time-sync.png` | ntpdate sync, -180 s step, Kali EST |
| 2 | `01-dc-asrep-user-created.png` | svc_file creation + DONT_REQUIRE_PREAUTH + UAC 4260352 + SID -1603 |
| 3 | `02-kali-getnpusers-roast.png` | GetNPUsers -request, UAC 0x410200, $krb5asrep$23$ hash, asrep_hashes.txt |
| 4 | `03-kali-hashcat-cracked.png` | hashcat 18200 Cracked → Password123, 325 kH/s, 0.26% progress |
| 5 | `04-wazuh-4768-list.png` | 4768 query, 20 hits, svc_file row + DESKTOP-B5RJ6HF6 baseline |
| 6 | `05-wazuh-4768-expanded-preauth0.png` | Expanded 4768 record 8654 — preAuthType 0, RC4 0x17, client .107:34658 |
