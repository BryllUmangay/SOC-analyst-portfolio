# 01 — Scenario

## Background

You are a Level-1 SOC analyst at a small company. A Windows 10 Home workstation (`winhome01`, `192.168.100.108`) is used by a finance employee and is exposed to the internal network with SMB file sharing enabled. An external attacker who has reached the internal network (assumed breach / rogue device at `192.168.100.107`) is performing password-guessing against the SMB service to obtain valid local credentials.

The workstation has the Wazuh agent installed. The Wazuh SIEM (`192.168.100.102`) collects Windows Security event logs and archives every raw event.

## Lab Setup (done once, before the attack)

### On Windows 10 Home (winhome01 — 192.168.100.108)

```powershell
# Run as Administrator

# 1. Enable File & Printer Sharing (SMB server) — required for the attack surface
Set-NetFirewallRule -DisplayGroup "File And Printer Sharing" -Enabled True

# 2. Enable admin shares (so post-exploitation verification works)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f

# 3. Create weak local accounts (brute-force targets)
net user jdoe "Password1" /add
net user mreyes "rockyou" /add
net user adminlab "P@ssw0rd" /add
net localgroup Administrators adminlab /add

# 4. (Optional but recommended) Enable account lockout so 4740 events fire
net accounts /lockoutthreshold:5 /lockoutwindow:5 /lockoutduration:10

# 5. Verify Wazuh agent + Sysmon running
Get-Service WazuhSvc, Sysmon* | Select Name, Status

# 6. Snapshot the VM: winhome01-baseline-clean
```

### On Wazuh SIEM (192.168.100.102)

- Confirm agent `winhome01` is **Active** (Dashboard → Agents).
- Confirm archives are enabled and `wazuh-archives-*` index pattern exists (see `SOC-Lab-Infrastructure/03-Wazuh-SIEM-Deployment.md`).
- Open Dashboard → Security Events and keep it visible during the attack.

### On Kali (192.168.100.107)

```bash
sudo apt install -y hydra netexec nmap smbclient impacket-scripts
# prepare wordlists
cat > ~/users.txt <<'EOF'
jdoe
mreyes
adminlab
administrator
guest
EOF
# password list — put the real one LAST so the attack ends with a success
cat > ~/pass.txt <<'EOF'
123456
password
Password1
qwerty
letmein
rockyou
Winter2024!
P@ssw0rd
EOF
```

> **Why the correct password is last:** a brute-force case is most realistic when it ends with a *successful* logon. The final `4624` success event right after a burst of `4625` failures is the classic "brute force succeeded" detection pattern — you want that in your evidence.

## Assumptions

- Kali has no Wazuh agent (attacker telemetry is victim-side only).
- Windows Home cannot be domain-joined; all accounts are local.
- No account lockout policy by default on Home — we enable it in step 4 above to generate `4740` lockout events.
