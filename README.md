# SOC Analyst Portfolio

A hands-on portfolio documenting security monitoring, alert triage, threat investigation, and detection engineering in a controlled home lab. The case studies trace activity from scenario and telemetry collection through analysis, findings, and remediation recommendations.

**Investigation workflow:** Scope → Baseline → Observe → Triage → Correlate → Assess → Document

> **Scope:** Attack simulations are conducted only on systems and networks owned by the author or explicitly authorized for testing. This portfolio demonstrates defensive learning and lab experience; it is not a claim of production SOC experience.

---

## Portfolio at a Glance

- **[SOC Lab Infrastructure](./SOC-Lab-Infrastructure/README.md)** — four-VM lab design, network topology, Wazuh deployment, Active Directory, setup, and connectivity validation.
- **Ten SOC investigation cases** — Windows endpoint, authentication, Active Directory, persistence, and process-behavior investigations.
- **Evidence-based documentation** — scenarios, attack simulations, observed telemetry, investigation notes, timelines, findings, and remediation recommendations.

## SOC Lab Infrastructure

The documented home lab uses an isolated `192.168.100.0/24` network with four virtual machines:

| Component | IP Address | Operating System | Role |
|---|---|---|---|
| Wazuh SIEM | `192.168.100.102` | Ubuntu Server | Centralized monitoring, indexing, and alert investigation |
| Kali Linux | `192.168.100.107` | Kali Linux | Authorized attack simulation |
| Windows endpoint | `192.168.100.108` | Windows 10/11 Home | Standalone workgroup endpoint |
| Domain Controller | `192.168.100.109` | Windows Server 2022 | Active Directory Domain Services and DNS |

The current infrastructure documentation describes the domain as `soclab.local`. The Wazuh manager collects endpoint telemetry through Wazuh agents, while Sysmon and Windows logging provide additional visibility.

The Windows Home endpoint remains workgroup-only because of its edition limitations. It is not domain-joined and does not support incoming Remote Desktop connections. The domain controller is used for Active Directory and remote domain-related exercises.

**Environment note:** The lab evolved as additional exercises were developed. Some case studies document earlier or separate configurations. For example, the Kerberoasting and AS-REP Roasting cases reference `BRYLL.LOCAL` and a domain controller at `192.168.100.105`, while the current infrastructure documentation describes `soclab.local` and `192.168.100.109`. Some endpoint investigations also use different recorded attacker IPs. These differences should be interpreted using each case's own documentation and evidence rather than assuming every exercise used an identical configuration.

Start with the [infrastructure overview](./SOC-Lab-Infrastructure/README.md), then see:

- [Network topology and traffic flows](./SOC-Lab-Infrastructure/01-Network-Topology.md)
- [VM build specifications](./SOC-Lab-Infrastructure/02-VM-Build-Specs.md)
- [Wazuh SIEM deployment and archives configuration](./SOC-Lab-Infrastructure/03-Wazuh-SIEM-Deployment.md)
- [Active Directory build](./SOC-Lab-Infrastructure/04-Active-Directory-Build.md)
- [Kali attacker setup](./SOC-Lab-Infrastructure/05-Kali-Attacker-Setup.md)
- [Screenshot checklist](./SOC-Lab-Infrastructure/06-Screenshot-Checklist.md)
- [Connectivity and telemetry validation](./SOC-Lab-Infrastructure/07-Validation-Connectivity.md)
- [Kali-to-Windows Home case plan](./SOC-Lab-Infrastructure/Kali-to-WinHome-Cases-Plan.md)

The infrastructure notes describe Wazuh 4.14.x all-in-one, Windows agents, Sysmon, PowerShell logging, and Wazuh JSON archives configured for raw-event investigation.

The documented VM hardware guidance assumes a host with 16 GB RAM and 8 CPU cores. Because of resource constraints, the infrastructure guide recommends running Wazuh, the domain controller, and one additional VM at a time where necessary.

## SOC Investigation Cases

The repository contains ten SOC investigation case studies. Each case has its own README and supporting investigation documents.

| Case | Investigation Focus | MITRE ATT&CK |
|---|---|---|
| [SMB Brute Force](./SOC-Case-Brute-Force-FINAL-v2/SOC-Case-Brute-Force/README.md) | Repeated SMB authentication failures, account lockout, successful network logons, and credential-attack analysis. The case documents a failed Hydra attempt and a successful NetExec run. | [T1110.001 – Password Guessing](https://attack.mitre.org/techniques/T1110/001/) |
| [Password Spraying](./SOC-Case-Password-Spraying/README.md) | SMB password attempts distributed across multiple accounts; analysis of authentication failures, successful logons, and the absence of account lockouts in the recorded run. | [T1110.003 – Password Spraying](https://attack.mitre.org/techniques/T1110/003/) |
| [Backdoor Account Creation](./SOC-Case-Account-Creation/README.md) | Masqueraded local account creation and addition of the account to the local Administrators group. | [T1136.001 – Local Account](https://attack.mitre.org/techniques/T1136/001/) · [T1098.007 – Additional Local or Domain Groups](https://attack.mitre.org/techniques/T1098/007/) |
| [Scheduled Task Persistence](./SOC-Case-Scheduled-Task/README.md) | Masqueraded and hidden scheduled task creation, including task registration, process execution, and persistence-related telemetry. | [T1053.005 – Scheduled Task](https://attack.mitre.org/techniques/T1053/005/) |
| [Suspicious PowerShell](./SOC-Case-Suspicious-PowerShell/README.md) | PowerShell download cradle, encoded execution, AMSI-bypass attempt, script-block logging, and network telemetry. The case distinguishes the attempted bypass from the run in which the download failed. | [T1059.001 – PowerShell](https://attack.mitre.org/techniques/T1059/001/) · [T1105 – Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) |
| [Windows Event Log Clearing](./SOC-Case-Event-Log-Clearing/README.md) | Windows Security, System, and Application log clearing; comparison of endpoint and SIEM evidence that remained available. | [T1070.001 – Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/) |
| [Kerberoasting](./SOC-Case-Kerberoasting/README.md) | Kerberos service-ticket investigation, RC4 ticket analysis, service principal names, and service-account exposure. | [T1558.003 – Kerberoasting](https://attack.mitre.org/techniques/T1558/003/) |
| [AS-REP Roasting](./SOC-Case-ASREP-Roasting/README.md) | Kerberos pre-authentication investigation, including an observed Event ID 4768 with `preAuthType: 0`. | [T1558.004 – AS-REP Roasting](https://attack.mitre.org/techniques/T1558/004/) |
| [DLL Search Order Hijacking](./SOC-Case-DLL-Hijacking/README.md) | Sysmon image-load investigation of an unsigned DLL loaded from a user-writable directory. | [T1574.001 – DLL Search Order Hijacking](https://attack.mitre.org/techniques/T1574/001/) |
| [Process Injection](./SOC-Case-Process-Injection/README.md) | CreateRemoteThread-based DLL injection investigated through Sysmon Event ID 8 and source-to-target process context. | [T1055.001 – Dynamic-link Library Injection](https://attack.mitre.org/techniques/T1055/001/) |

**Case completion:** A completed case means the lab exercise and its documented investigation were carried out. It does not mean every proposed detection is production-ready, every expected event was captured, or every case generated a real-time alert. Refer to the individual case documents for the actual results, evidence, and limitations.

## Investigation Methodology

The case studies follow an evidence-led approach designed to reflect common SOC L1 investigation activities.

1. **Scope the scenario:** Identify the systems involved, expected behavior, attack objective, and defensive question. Ensure that all simulation activity remains within the authorized lab.
2. **Establish a baseline:** Check host connectivity, endpoint-agent health, relevant audit and logging configuration, and system time.
3. **Record the activity:** Preserve simulation steps and command records where available. Do not treat an intended action as proof that it succeeded.
4. **Validate collection:** Confirm whether endpoint events were generated and whether they reached Wazuh. A missing alert does not prove that no activity occurred.
5. **Triage and correlate:** Examine event fields, account and host context, source and destination addresses, process ancestry, timestamps, and surrounding activity. Use raw archives where available to investigate events that did not generate alerts.
6. **Assess the evidence:** Separate directly observed facts from interpretations. Document missing artifacts, clock or time-zone issues, and alternative explanations.
7. **Document findings and response:** Explain the impact supported by evidence, investigation gaps, containment or remediation recommendations, and potential detection improvements.

## Telemetry Sources

Telemetry sources vary by case and by what was actually captured.

### Windows Security and Active Directory

Examples of Windows event IDs examined include:

| Event ID | Description | Investigation Focus |
|---|---|---|
| 4624 | Successful logon | Authentication success and logon type |
| 4625 | Failed logon | Authentication failures and credential attacks |
| 4740 | Account locked out | Account lockout correlation |
| 4720 | User account created | Account creation and persistence |
| 4732 | Member added to a security-enabled local group | Privilege and group membership changes |
| 4768 | Kerberos authentication ticket requested | TGT and pre-authentication analysis |
| 4769 | Kerberos service ticket requested | TGS activity and Kerberoasting |
| 4698 | Scheduled task created | Persistence investigation |
| 1102 | Audit log cleared | Security log clearing |
| 104 | Event log cleared | System and Application log clearing |

### Sysmon

Depending on the case, Sysmon provides additional endpoint telemetry:

| Event ID | Description | Investigation Focus |
|---|---|---|
| 1 | Process creation | Process execution, command lines, and parent-child relationships |
| 3 | Network connection | Process-associated network activity |
| 7 | Image loaded | DLL loading and suspicious module paths |
| 8 | CreateRemoteThread | Process injection activity |
| 11 | File created | File creation and staged payloads |

Some event types are recommended investigative pivots rather than evidence captured in every exercise.

### PowerShell

PowerShell Script Block Logging, including Event ID 4104, is used where configured and observed. This helps examine command execution, encoded content, and suspicious scripting activity.

### Wazuh

Wazuh is used for:

- Endpoint log collection and centralized monitoring.
- Security Events and rule-triggered alerts.
- Indexed event searches and investigation.
- Raw JSON event archives through `wazuh-archives-*`, where enabled.
- Hunting queries and correlation of activity across available telemetry.

Event IDs and ATT&CK mappings are investigation pivots, not standalone proof of malicious activity. Interpret them using event fields, host context, surrounding activity, and corroborating evidence.

## Detection Engineering and Validation

The case documents distinguish between observed alerts, proactive hunting, and proposed detection logic.

### 1. Observed Wazuh alerts

Examples supported by the case documentation include:

- **SMB Brute Force:** Wazuh rule `18106` fired on individual Windows Event ID 4625 authentication failures. The case documents no captured high-severity correlation alert for the full brute-force sequence.
- **Windows Event Log Clearing:** Wazuh rule `63103` fired for Event ID 1102 at level 5. The case identifies this severity as insufficient for the significance of the activity.

These are documented observations from the lab, not claims of production-ready detection coverage.

### 2. Observed telemetry and proactive hunting

An event appearing in Wazuh or being found in `wazuh-archives-*` does not automatically mean that a Wazuh alert fired.

Examples include:

- **DLL Search Order Hijacking:** Sysmon Event ID 7 was identified using a proactive hunting query against Wazuh archives. The case explicitly states that no real-time Wazuh alert fired.
- **Process Injection:** Sysmon Event ID 8 was identified through an archives hunting query using the `startFunction` field. The case explicitly states that no real-time Wazuh alert fired.

Other cases document event observations, searches, and correlation. Refer to each case's Alert and Investigation documents to distinguish what actually fired from what was discovered through hunting.

### 3. Proposed custom detection rules

Some case documents include:

- Custom Wazuh XML rules.
- Wazuh rule overrides and correlation examples.
- Sigma detection examples.
- Recommended archive-hunting queries.
- Suggested detection improvements and remediation controls.

These are proposals unless the corresponding case includes evidence that the rule was tested successfully.

**A proposed detection rule should not be described as validated simply because its configuration is documented.**

### Detection validation workflow

Before considering a custom rule validated, test it in the target environment:

1. Confirm the decoded event fields and parent-rule behavior for the installed Wazuh version.
2. Verify XML syntax and successful rule loading.
3. Test representative matching and non-matching events using appropriate tooling, such as `wazuh-logtest`.
4. Confirm the expected alert appears in Wazuh.
5. Inspect the resulting rule ID, severity, decoded fields, and MITRE ATT&CK mapping.
6. Test benign lookalike events and document false positives.
7. Record coverage boundaries, limitations, and the actual test results.

This portfolio does not claim that all proposed custom Wazuh or Sigma rules have passed runtime validation.

## Repository Structure

The following reflects the current organization of the repository:

```text
SOC-analyst-portfolio/
│
├── README.md
│
├── SOC-Lab-Infrastructure/
│   ├── README.md
│   ├── 01-Network-Topology.md
│   ├── 02-VM-Build-Specs.md
│   ├── 03-Wazuh-SIEM-Deployment.md
│   ├── 04-Active-Directory-Build.md
│   ├── 05-Kali-Attacker-Setup.md
│   ├── 06-Screenshot-Checklist.md
│   ├── 07-Validation-Connectivity.md
│   ├── Kali-to-WinHome-Cases-Plan.md
│   └── screenshots/
│
├── SOC-Case-ASREP-Roasting/
│
├── SOC-Case-Account-Creation/
│
├── SOC-Case-Brute-Force-FINAL-v2/
│   └── SOC-Case-Brute-Force/
│
├── SOC-Case-DLL-Hijacking/
│
├── SOC-Case-Event-Log-Clearing/
│
├── SOC-Case-Kerberoasting/
│
├── SOC-Case-Password-Spraying/
│
├── SOC-Case-Process-Injection/
│
├── SOC-Case-Scheduled-Task/
│
└── SOC-Case-Suspicious-PowerShell/
```

Each case directory contains a README and numbered investigation documents. Evidence directories and `kali-commands.txt` files are present where applicable.

The brute-force case README is located at:

`SOC-Case-Brute-Force-FINAL-v2/SOC-Case-Brute-Force/README.md`

Start with the individual case README, then follow the numbered documents for the scenario, simulation, alerts, indicators, investigation, timeline, analysis, conclusion, and remediation.

## Tools and Technologies

| Category | Technologies |
|---|---|
| SIEM and monitoring | Wazuh 4.14.x, Wazuh agents, Filebeat, indexed alerts, and raw archives |
| Lab operating systems | Kali Linux, Windows 10/11 Home, Windows Server 2022, Ubuntu Server |
| Virtualization | VirtualBox and VMware Workstation |
| Endpoint logging | Sysmon, Windows Security auditing, Windows Event Viewer, PowerShell logging |
| Network investigation | Nmap, SMB enumeration tools, Wireshark |
| Active Directory | AD DS, DNS, Kerberos, SMB, LDAP, and SPN-based service-account investigations |
| Analysis and documentation | Wazuh Discover, event correlation, timelines, indicators, MITRE ATT&CK, Markdown, Git, and GitHub |

Tools are listed to describe their use in the documented lab exercises. Their inclusion does not imply production deployment experience or expert-level proficiency.

## Evidence and Reproducibility

Case folders organize the available scenario, simulation, alert, indicator, investigation, timeline, analysis, conclusion, and remediation documents.

Screenshots support specific observations, while command notes record lab activity where available.

Use individual case documents for exact event fields, host information, timestamps, observed outcomes, and evidence limitations.

Some cases explicitly identify missing corroborating telemetry, uncaptured timestamps, or findings obtained through hunting queries rather than real-time alerts. Missing evidence is not inferred or represented as a confirmed result.

## Safety and Lab Use

- All attack simulations are restricted to systems and networks owned by the author or covered by explicit authorization.
- Attack tools and payload exercises are used for defensive learning and observation in controlled environments.
- Lab IP addresses, hostnames, usernames, and indicators are artifacts of these exercises and should not be interpreted as verified real-world threat intelligence.
- Lab credentials should never be reused in production environments.
- Credentials, tokens, passwords, private keys, and other secrets must not be committed to this public repository.
- Findings and detection recommendations are educational case documentation, not a substitute for production security review or incident-response procedures.

## About

An ongoing learning portfolio focused on SOC analysis, SIEM monitoring, Windows and Active Directory telemetry, and evidence-based threat investigation.

**Author:** Bryll Wrex Umangay  
**Focus:** SOC Analysis · SIEM Monitoring · Windows Security Events · Active Directory · Threat Investigation

---

*This repository is updated as additional lab exercises, detections, and investigation write-ups are completed.*
