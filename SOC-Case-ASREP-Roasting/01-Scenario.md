# 01 — Scenario
## Environment
- **Domain:** `BRYLL.LOCAL` (bryll.local), Domain SID `S-1-5-21-1845810679-4027539410-2363447484`
- **Domain Controller:** `WIN-BPME02TD5L2.bryll.local` / `192.168.100.105`, Wazuh agent `Windows-server` (agent.id 003), Sysmon + Advanced Audit Policy (Kerberos Authentication Service / Kerberos Service Ticket Operations auditing enabled).
- **Domain-joined workstation:** `DESKTOP-B5RJ6HF6` (Win10 Pro, `192.168.100.110`) — generates normal baseline 4768 events.
- **Attacker:** Kali (`butch@butch`), observed source IP **`192.168.100.107`** (DHCP — document as observed), Impacket v0.13.1, hashcat, rockyou.txt.
- **SIEM:** Wazuh manager `192.168.100.102`, archives enabled (`logall_json yes`), index pattern `wazuh-archives-*`, query language **DQL**.

## Story
A file-share service account `svc_file` was provisioned with a weak password and — critically — the **"Do not require Kerberos preauthentication"** flag set (UserAccountControl `0x400000`). This is a legacy compatibility setting (used by some old Unix/embedded appliances) that disables the encrypted-timestamp pre-auth step in the Kerberos AS exchange. Any unauthenticated attacker can send an AS-REQ for that account and receive an AS-REP encrypted with the account's NTLM key — which can be cracked offline. No special rights, no interactive logon, no logon failures are generated.

An attacker who already owns a low-priv domain user (`jdoe`) uses it to bind/LDAP-enumerate accounts with the `DONT_REQUIRE_PREAUTH` flag, then roasts `svc_file`, cracks its password, and obtains a valid domain credential.

## Vulnerable account setup (DC, Administrator PowerShell) — actual
📸 `evidence/01-dc-asrep-user-created.png`
```powershell
# Create the weak service account (password never expires = typical service account)
New-ADUser -Name svc_file -SamAccountName svc_file -Enabled $true `
  -PasswordNeverExpires $true `
  -AccountPassword (ConvertTo-SecureString 'Password123' -AsPlainText -Force)

# The dangerous bit: exempt from Kerberos pre-authentication
Set-ADAccountControl -Identity svc_file -DoesNotRequirePreAuth $true

# Verify
Get-ADUser svc_file -Properties DoesNotRequirePreAuth, UserAccountControl
```
Verified properties (actual):
| Property | Value |
|---|---|
| DistinguishedName | `CN=svc_file,CN=Users,DC=bryll,DC=local` |
| SamAccountName / Name | `svc_file` |
| ObjectGUID | `c57a3e1c-13a0-478a-855e-3b799b04fa15` |
| SID | `S-1-5-21-1845810679-4027539410-2363447484-1603` |
| Enabled / DoesNotRequirePreAuth | True / **True** |
| PasswordNeverExpires | True |
| **UserAccountControl** | **4260352 (0x410200)** = `DONT_REQUIRE_PREAUTH`(0x400000) + `DONT_EXPIRE_PASSWORD`(0x10000) + `NORMAL_ACCOUNT`(0x200) |

**Why this matters:** the `0x400000` bit is the entire vulnerability. Find it with: `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth`.
