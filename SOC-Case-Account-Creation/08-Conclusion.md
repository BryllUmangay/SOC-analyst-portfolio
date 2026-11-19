# 08 — Conclusion

## Findings

1. **High — Persistent backdoor admin account created and confirmed functional.** `svc_backup` (SID -1011), never expires, member of Administrators; `netexec` login → `(Pwn3d!)`. Survives reboots and credential rotation of the original admin.
2. **Medium — Masquerading (T1036):** account named/commented to look like a backup service account.
3. **Medium — Anomalous creator:** account created by SYSTEM/machine context (`DESKTOP-F0JVTQT$`, S-1-5-18), not a human admin — indicates post-execution tooling (psexec).
4. **Medium — SID correlation detection:** member SID in 4732 (-1011) = target SID in 4720 — proves the same account was created then promoted to admin.
5. **Medium — No high-severity built-in alert** on 4720→4732 sequence; custom correlation rule required.
6. **Low — Time sync offset** persists.

## Severity: High

A backdoor admin account is the most durable persistence technique — even after removing psexec and rotating `adminlab`, the attacker retains access via `svc_backup`. In a real environment this requires full IR: identify all unknown local admins, rotate all credentials, threat-hunt for use of the backdoor SID across all hosts.

## What went well

- 4720 + 4732 both logged (default auditing — no special config needed).
- SID correlation (-1011) ties creation to admin promotion — definitive evidence.
- Sysmon captured full `net.exe` command lines + hashes; SwiftOnSecurity auto-tagged **T1098.007** on the admin-add.
- Backdoor **functionality proven** via `netexec (Pwn3d!)` — not just theoretical.

## Lessons learned

1. **Hunt for local admin accounts created by SYSTEM/machine context** — anomalous creator is the highest-fidelity signal.
2. **Correlate 4720 → 4732 by SID** — a new account added to Administrators within a short window = backdoor until proven otherwise.
3. **Audit "never expires" accounts** — `/expires:never` on a non-service account is suspicious.
4. **Baseline local Administrators membership** — alert on any new member (4732 targeting S-1-5-32-544).
5. **Custom Wazuh correlation rules required** — built-in rules don't catch the 4720→4732 sequence at high severity (09-Remediation).

## Post-case actions

- [x] Deleted `svc_backup` (`net user /delete`); removed from Administrators.
- [x] Rotated `adminlab` password.
- [x] Documented custom detection rule (09).
- [x] Rolled back to `winhome01-baseline-clean`.
