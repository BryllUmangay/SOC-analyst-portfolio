# 09 — Remediation & Detection Engineering

## Immediate containment

- Reset `svc_sql` password (25+ chars, random). Rotate `jdoe`.
- Hunt: `data.win.system.eventID: 4769 and data.win.eventdata.ticketEncryptionType: "0x17"` — find all RC4 TGS requests; identify other roasted accounts.
- Check `svc_sql` logon activity (4624) — did attacker use it after cracking?

## Hardening (stops kerberoasting cold)

1. **AES-only service accounts:** set `msDS-SupportedEncryptionTypes = 24` (AES128+AES256, no RC4) on all SPN accounts. TGS then uses AES (0x12/0x11) — not crackable by this method.
2. **Use gMSA (Group Managed Service Accounts)** — auto-rotated 120-char passwords, unbreakable. Preferred for all services.
3. **Long random service-account passwords** (25+ chars) — even RC4 hashes become uncrackable in practice.
4. **Least privilege for service accounts** — if cracked, they can't do much.
5. **Clean up stale SPNs** (`setspn -Q */*`) — remove unused; every user-account SPN is a target.
6. **Fix DC NTP** — authoritative time source; Kerberos breaks >5 min skew.
7. **Monitor SPN creation** (Event ID 4742/5136) — alert on new SPNs on user accounts.

## Custom Wazuh rule — alert on RC4 TGS (kerberoasting)

`/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="windows,kerberoasting,">
  <!-- High: 4769 TGS with RC4 encryption (0x17) = roastable ticket -->
  <rule id="100260" level="10">
    <field name="win.system.eventID">^4769$</field>
    <field name="win.eventdata.ticketEncryptionType">^0x17$</field>
    <description>Kerberos TGS requested with RC4 (0x17) — possible Kerberoasting (T1558.003). SPN: %win.eventdata.serviceName, client: %win.eventdata.ipAddress.</description>
    <mitre><id>T1558.003</id></mitre>
  </rule>

  <!-- Critical: many RC4 TGS from one client in short window = automated roasting -->
  <rule id="100261" level="13" frequency="10" timeframe="120">
    <if_sid>100260</if_sid>
    <same_field>win.eventdata.ipAddress</same_field>
    <description>Multiple RC4 TGS requests (10+/2min) from single client — automated Kerberoasting tool (Rubeus/Impacket).</description>
    <mitre><id>T1558.003</id></mitre>
  </rule>
</group>
```
`sudo systemctl restart wazuh-manager`

## Sigma rule (portable)

```yaml
title: Kerberoasting — RC4 TGS Request
id: 00000000-0000-0000-0000-000000000007
status: test
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
  filter_legit_computers:
    ClientAddress|startswith: '::ffff:192.168.100.'   # your managed subnet; alert on EXTERNAL/unmanaged
  condition: selection and not filter_legit_computers
falsepositives:
  - Legacy services requiring RC4 (migrate to AES)
level: high
tags: [attack.credential_access, attack.t1558.003]
```

## Hunting query (Wazuh DQL)

```
data.win.system.eventID: 4769 and data.win.eventdata.ticketEncryptionType: "0x17"
| stats count by data.win.eventdata.ipAddress, data.win.eventdata.serviceName
| where count > 5 → likely automated roasting.
```
