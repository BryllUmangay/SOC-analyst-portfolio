# 08 — Conclusion

## Findings

1. **High — Kerberoasting successful.** `svc_sql` service-account hash (RC4 etype 23) captured and cracked to `Password123` in ~1 sec using only low-privilege `jdoe`. Service account compromised.
2. **Medium — RC4 (0x17) encryption in use** (TGT + TGS) — AES not enforced; every RC4 SPN account is crackable.
3. **Medium — No built-in high-severity alert** for 4769 RC4; custom detection required.
4. **Medium — DC time skew** (~3 days) broke Kerberos until ntpdate; fix DC NTP.
5. **Low — SPN inventory/cleanup needed** (host label mismatch).

## Severity: High

Kerberoasting yields valid service-account credentials with zero code execution and near-zero noise. In a real environment: reset `svc_sql`, hunt for other RC4 SPNs, check `svc_sql` usage (where could it log in?), and treat any 4769 RC4 from unmanaged IPs as active credential access.

## What went well

- **4769 + 4768 both logged** (audit policy enabled) with full fields — definitive detection.
- **Consecutive eventRecordIDs (7567→7568) + matching logonGuid** — textbook correlation.
- **RC4 0x17 clearly visible** — the detection signature.
- **Full attack chain proven**: enum → roast → crack (Password123) — not theoretical.
- Documented the **clock-skew failure honestly** (first attempt failed) — shows troubleshooting.

## Lessons learned

1. **Hunt for `ticketEncryptionType: 0x17` in 4769** — that's the kerberoasting signature.
2. **Service accounts = the crown jewels** — long (25+ char), rotated, AES-only passwords; consider Group Managed Service Accounts (gMSA) which auto-rotate 120-char passwords.
3. **Set `msDS-SupportedEncryptionTypes = 24` (AES only)** on service accounts → TGS becomes AES, uncrackable by this method.
4. **Any domain user can roast** — least privilege doesn't stop it; strong service-account passwords do.
5. **Correlate 4768→4769 by logonGuid/eventRecordID** — proves same session.
6. **Fix DC time** — Kerberos breaks with >5 min skew.

## Post-case actions

- [x] Reset `svc_sql` to 25+ char password; set AES-only.
- [x] Rotated `jdoe`.
- [x] Documented custom Wazuh rule (09).
- [x] DC NTP configured (w32tm resync).
- [x] Rolled back to clean baseline.
