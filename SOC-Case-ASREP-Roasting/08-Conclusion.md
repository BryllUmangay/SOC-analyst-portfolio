# 08 — Conclusion
## Verdict
**Confirmed AS-REP Roasting (T1558.004) → successful credential compromise.** Severity **High**.

The domain account `svc_file` (SID `...-1603`) was configured with `DONT_REQUIRE_PREAUTH` (UAC `0x410200`) and a weak password (`Password123`). An attacker on `192.168.100.107` used Impacket `GetNPUsers.py -request` to harvest its RC4 AS-REP (`$krb5asrep$23$...`) and cracked it with hashcat mode 18200 in ~39 s (0.26% of rockyou.txt). The attack produced **zero logon failures** and is visible only as a 4768 Audit-Success event with **`preAuthType=0`** + `ticketEncryptionType=0x17` (eventRecordID 8654, client `::ffff:192.168.100.107:34658`).

## What went right (detection)
- DC Advanced Audit Policy captured Kerberos AS events (4768) to the Security log.
- Wazuh agent `Windows-server` forwarded them; archives (`logall_json`) preserved full event fields including `preAuthType` and `ticketEncryptionType`.
- SID correlation (`targetSid ...-1603` = `svc_file`) and UAC bit (`0x400000`) confirmed the vulnerable account end-to-end.

## What went wrong (exposure)
- `DONT_REQUIRE_PREAUTH` set on a regular user account — unnecessary and dangerous.
- Weak, never-expiring service-account password (`Password123`).
- RC4 (etype 23) accepted — AES not enforced; the AS-REP is crackable.
- No detection rule on `preAuthType=0` — the attack would have been missed in real time; found only via retroactive hunting query.

## Lessons for the SOC
1. **Hunt `preAuthType=0` weekly** — `data.win.system.eventID: 4768 and data.win.eventdata.preAuthType: "0"`. It is the cheapest, highest-fidelity Kerberos-abuse hunt there is.
2. **Audit `DONT_REQUIRE_PREAUTH` accounts** — `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true}`; the list should be empty or limited to documented legacy appliances.
3. **Pair with Kerberoasting hunting** (4769 RC4 0x17, Case 1) — together they cover both offline-credential theft vectors.
4. **Enforce AES + long random passwords** on all service accounts; prefer gMSA.
5. **Timezone discipline** — normalize all timestamps to UTC during analysis (here Kali/DC EST vs Wazuh PHT = 13 h offset).

## Next cases (Week 2)
3. LLMNR/NBT-NS Poisoning (Responder) → 4. SMB Relay (ntlmrelayx) → 5. DCSync (4662) → 6. LSASS Dump (Sysmon 10) → 7. Pass-the-Hash → ...
