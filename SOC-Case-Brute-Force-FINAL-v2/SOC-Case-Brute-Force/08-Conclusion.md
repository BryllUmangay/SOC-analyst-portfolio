# 08 — Conclusion

## Findings

1. **Finding 1 (Critical):** Successful brute-force compromise of local administrator `adminlab` from `192.168.100.107`. Evidence: burst of 4625 → 4624 (type 3) as adminlab.
2. **Finding 2 (High):** Weak password policy — `P@ssw0rd` (common, in rockyou) accepted for an admin account. No minimum-length/complexity enforcement on Home (local policy limited).
3. **Finding 3 (Medium):** SMB file sharing exposed to the network with no network-level restrictions; admin shares (ADMIN$) accessible.
4. **Finding 4 (Medium, before fix):** No account lockout policy by default on Windows Home. After enabling it, lockouts (4740) occurred as expected.

## Severity rating

**Critical** — attacker obtained local admin credentials on a workstation that handles finance data. In a real environment this is a foothold for lateral movement (when AD is present).

## What went well (detection)

- Wazuh agent collected Security logs in real time.
- Rule 18106 fired on every 4625; correlation rule flagged the burst.
- Archives (`wazuh-archives-*`) preserved every raw attempt for forensics — including attempts that never generated a separate alert.
- The 4624 success event allowed confirmation of compromise within minutes.

## Lessons learned

1. A brute-force case is only complete when you show **both** the failure burst **and** the final success. Without the success, it's just a noisy scan.
2. Logon Type 3 + source IP in 4625 is the fastest way to attribute SMB brute force.
3. Windows Home's lack of account lockout by default is itself a finding — always enable it and document it.
4. The `adminlab` password being in the wordlist demonstrates why password-complexity + lockout + MFA are all needed (defense in depth).

## Post-case actions

- [ ] Rotate `adminlab` and all tested account passwords.
- [ ] Keep account lockout policy enabled.
- [ ] Restrict SMB (445) to trusted IPs via Windows Firewall.
- [ ] Deploy the custom Wazuh rule in `09-Remediation.md`.
- [ ] Roll back to `winhome01-baseline-clean` snapshot for the next case.
