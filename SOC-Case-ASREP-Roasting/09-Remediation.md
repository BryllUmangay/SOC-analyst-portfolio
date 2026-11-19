# 09 — Remediation & Detection Engineering
## Immediate containment
- **Reset `svc_file`** password (25+ random chars) and **clear the pre-auth exemption**:
  ```powershell
  Set-ADAccountControl -Identity svc_file -DoesNotRequirePreAuth $false
  Set-ADAccountPassword -Identity svc_file -Reset -NewPassword (ConvertTo-SecureString '<25+ random>' -AsPlainText -Force)
  ```
- Rotate `jdoe` (the enumeration account).
- Hunt: `data.win.system.eventID: 4768 and data.win.eventdata.preAuthType: "0"` — find ALL roasted accounts; check each for post-crack logons (4624).
- Audit `svc_file` group memberships/ACLs — revoke excess privilege.

## Hardening (stops AS-REP roasting cold)
1. **Remove `DONT_REQUIRE_PREAUTH` from every account** — audit and remediate:
   ```powershell
   Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth, UserAccountControl |
     Set-ADAccountControl -DoesNotRequirePreAuth $false
   ```
   Keep exempt only documented legacy appliances, and give those 30+ char random passwords.
2. **Enforce AES** — set `msDS-SupportedEncryptionTypes = 24` (AES128+AES256, no RC4) domain-wide via GPO; disable RC4 (Network security: Configure encryption types allowed for Kerberos). RC4 AS-REPs are the crackable blob.
3. **Long random service-account passwords** (25+ chars) or **gMSA** (auto-rotated 120-char) — even if roasted, uncrackable.
4. **Least privilege** for service accounts — if cracked, blast radius is small.
5. **Fix DC NTP** — authoritative time source; Kerberos breaks >5 min skew (Kali was 180 s off here).
6. **Monitor account-control changes** — Event ID **4738** (user account changed) alert on `DoesNotRequirePreAuth` being set; it should never happen silently.

## Custom Wazuh rule — alert on preAuthType=0 (AS-REP Roasting)
`/var/ossec/etc/rules/local_rules.xml` (next free IDs after Kerberoasting 100260/100261):
```xml
<group name="windows,asrep_roasting,">
  <!-- High: 4768 TGT requested with NO pre-authentication (preAuthType=0) = roastable AS-REP -->
  <rule id="100262" level="12">
    <field name="win.system.eventID">^4768$</field>
    <field name="win.eventdata.preAuthType">^0$</field>
    <description>AS-REP Roasting (T1558.004): Kerberos TGT (4768) requested with NO pre-authentication for account "%win.eventdata.targetUserName" from %win.eventdata.ipAddress:%win.eventdata.ipPort. RC4=%win.eventdata.ticketEncryptionType.</description>
    <mitre><id>T1558.004</id></mitre>
  </rule>
  <!-- Critical: many preAuthType=0 requests from one client in short window = automated sweep -->
  <rule id="100263" level="14" frequency="5" timeframe="60">
    <if_sid>100262</if_sid>
    <same_field>win.eventdata.ipAddress</same_field>
    <description>AS-REP Roasting sweep: 5+ preAuthType=0 TGT requests in 60s from single client %win.eventdata.ipAddress (Rubeus/Impacket).</description>
    <mitre><id>T1558.004</id></mitre>
  </rule>
</group>
```
`sudo systemctl restart wazuh-manager`

## Sigma rule (portable)
```yaml
title: AS-REP Roasting — TGT Requested Without Pre-Authentication
id: 00000000-0000-0000-0000-000000000008
status: test
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4768
    PreAuthType: 0
  filter_known_legacy_appliances:
    TargetUserName:
      - svc_legacy_unix      # your documented exempt accounts
  condition: selection and not filter_known_legacy_appliances
falsepositives:
  - Documented legacy appliances explicitly exempted from pre-auth
level: high
tags: [attack.credential_access, attack.t1558.004]
```

## Hunting queries (Wazuh DQL)
```
# Highest fidelity — active roasting:
data.win.system.eventID: 4768 and data.win.eventdata.preAuthType: "0"

# Roastable RC4 AS-REPs (correlate with above):
data.win.system.eventID: 4768 and data.win.eventdata.ticketEncryptionType: "0x17"

# Watch for the exemption bit being set (4738 = account changed):
data.win.system.eventID: 4738
```
