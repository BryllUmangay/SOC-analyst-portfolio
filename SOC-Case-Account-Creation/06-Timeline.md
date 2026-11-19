# 06 — Timeline (actual, from evidence)

Note: account creation (Oct 30) and admin-group add (Oct 31) occurred in separate sessions; both captured. Windows local vs Sysmon UTC offset persists (~7h; NTP finding).

| # | Time | Event | Source | Evidence filename |
|---|---|---|---|---|
| 1 | 2026-10-30 | `impacket-psexec adminlab` → SYSTEM shell (service `Wlug`, `DmmYUPVU.exe`) | Kali | `1-kali-psexec-shell.png` |
| 2 | 2026-10-30 14:52:14.298Z (Sysmon UTC) | `net user svc_backup ... /add /expires:never` executed — Sysmon Event ID 1 (net.exe, processId 12436) | winhome01 → Wazuh | `10-wazuh-sysmon-1-net-exe.png` |
| 3 | 10/30/2026 7:52:15 AM (Windows local) | **Event ID 4720** — account `svc_backup` created (SID -1011), subject SYSTEM (DESKTOP-F0JVTQT$) | winhome01 → Wazuh | `07-wazuh-4720-account-created.png`, `12-windows-eventviewer-4720-4732.png` |
| 4 | post-create | `net user svc_backup` verify: active Yes, expires Never, member Administrators+Users | Kali | `04-kali-verify-account.png` |
| 5 | 2026-10-31 15:53:37.056Z (Sysmon UTC) | `net localgroup Administrators svc_backup /add` executed — Sysmon Event ID 1 (net.exe, processId 1568), tagged T1098.007 | winhome01 → Wazuh | `10-wazuh-sysmon-1-net-exe.png` |
| 6 | 2026-10-31T15:53:39.245Z (≈8:53:39 AM local) | **Event ID 4732** — member SID -1011 (svc_backup) added to Administrators (S-1-5-32-544), eventRecordID 4390 | winhome01 → Wazuh | `08-wazuh-4732-added-to-admins.png`, `12-windows-eventviewer-4720-4732.png` |
| 7 | post-add | `netexec smb -u svc_backup -p 'B@ckupSvc2026!'` → `(Pwn3d!)` — backdoor admin access confirmed | Kali | `05-kali-backdoor-login-test.png` |
| 8 | containment | `net user svc_backup /delete` (Event ID 4726 if logged); adminlab rotated; audit for unknown admins | winhome01 | — |

## Key correlation chain

`psexec (SYSTEM) → net user /add (Sysmon 1) → 4720 (svc_backup, SID -1011, subject=machine) → [next session] net localgroup Administrators /add (Sysmon 1, T1098.007) → 4732 (member SID -1011 = same account) → netexec login as svc_backup succeeds (Pwn3d!)`. The SID `-1011` ties creation to admin promotion.
