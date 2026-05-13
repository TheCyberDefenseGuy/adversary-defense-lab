# APT29 — Cozy Bear

> Complete profile of the APT29 threat group, also known as Cozy Bear, including real campaign history, targets, most used TTPs and geopolitical context.

---

## Identification

| Attribute | Detail |
|---|---|
| Name | APT29 |
| Aliases | Cozy Bear, The Dukes, Midnight Blizzard, NOBELIUM, Dark Halo |
| Origin | Russia |
| Sponsor | SVR — Foreign Intelligence Service of Russia |
| Active since | 2008 |
| Motivation | Political, economic and military espionage |
| Primary targets | Governments, think tanks, NGOs, technology, healthcare and energy companies |

---

## Context

APT29 is one of the most sophisticated and active advanced persistent threat groups in the world. It operates under the control of the Russian SVR and its primary mission is the collection of strategic intelligence to support Russian state interests. Unlike financially motivated groups, APT29 focuses on long-duration operations where persistence and stealth have more value than immediate impact.

The group is known for developing its own tools, adapting its techniques rapidly after public exposure, and using legitimate infrastructure such as cloud services and well-known platforms to mask its C2 communications.

---

## Known Campaigns

### SolarWinds — SUNBURST (2020)

The most impactful APT29 campaign was the SolarWinds supply chain compromise. The group injected malicious code into the SolarWinds Orion software which was distributed as a legitimate update to approximately 18,000 organisations including multiple US government agencies such as the State Department, Treasury and Department of Homeland Security.

The attack remained undetected for approximately 9 months and is considered one of the most sophisticated cyber espionage operations ever documented.

Reference: [CISA Alert AA20-352A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a)

### Democratic National Committee Hack (2016)

APT29 compromised DNC systems together with APT28 during the 2016 US presidential elections. The group maintained silent access for months while collecting emails and internal documents.

Reference: [CrowdStrike Report — Bears in the Midst](https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/)

### COVID-19 Research Targeting (2020)

During the pandemic APT29 conducted spearphishing campaigns against vaccine research organisations in the United Kingdom, Canada and the United States. The UK NCSC, Canadian CSE and US NSA published a joint advisory identifying the group.

Reference: [NCSC Advisory — APT29 targets COVID-19 vaccine research](https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-research)

### Microsoft and Technology Companies (2023-2024)

The group compromised executive email accounts at Microsoft through password spraying and access to legacy OAuth applications. Microsoft identified the group as Midnight Blizzard and reported that initial access occurred in November 2023 and was discovered in January 2024.

Reference: [Microsoft Security Blog — Midnight Blizzard](https://msrc.microsoft.com/blog/2024/01/microsoft-actions-following-attack-by-nation-state-actor-midnight-blizzard/)

### TeamViewer (2024)

APT29 compromised internal TeamViewer systems using credentials from an employee account. The company confirmed the incident in June 2024.

---

## Most Used TTPs

APT29 uses a consistent set of techniques across its campaigns. The table below shows the most frequent TTPs mapped in MITRE ATT&CK.

| TTP | Technique | Tactic |
|---|---|---|
| T1566.001 | Spearphishing Attachment | Initial Access |
| T1566.002 | Spearphishing Link | Initial Access |
| T1059.001 | PowerShell | Execution |
| T1059.003 | Windows Command Shell | Execution |
| T1027 | Obfuscated Files | Defense Evasion |
| T1036 | Masquerading | Defense Evasion |
| T1078 | Valid Accounts | Defense Evasion |
| T1071.001 | Web Protocols | Command and Control |
| T1102 | Web Service | Command and Control |
| T1547.001 | Registry Run Keys | Persistence |
| T1547.009 | Shortcut Modification | Persistence |
| T1003 | OS Credential Dumping | Credential Access |
| T1087 | Account Discovery | Discovery |
| T1560 | Archive Collected Data | Collection |
| T1105 | Ingress Tool Transfer | Command and Control |

Full reference: [MITRE ATT&CK — APT29](https://attack.mitre.org/groups/G0016/)

---

## Associated Tools and Malware

| Tool | Type | Description |
|---|---|---|
| SUNBURST | Backdoor | Injected into the SolarWinds supply chain |
| SUNSHUTTLE | Backdoor | Second stage after SUNBURST |
| TEARDROP | Loader | Loads Cobalt Strike in memory |
| MiniDuke | Backdoor | Used in campaigns against European governments |
| CosmicDuke | Infostealer | Credential and document collection |
| WellMess | RAT | Used in campaigns against COVID-19 research |
| WellMail | RAT | WellMess variant |
| Cobalt Strike | Framework | Extensively used for post-compromise C2 |

---

## Infrastructure and C2

APT29 is known for using legitimate infrastructure to mask its communications and make attribution and blocking more difficult. Documented techniques include using legitimate cloud services such as OneDrive, Dropbox and Google Drive as C2 channels, registering domains that mimic legitimate services such as software updates, using valid TLS certificates for HTTPS in C2 communications and frequently rotating infrastructure after exposure.

---

## Distinctive Characteristics

APT29 distinguishes itself from other APT groups through several characteristics that make its detection and attribution particularly difficult.

The group has exceptional operational patience and maintains access to compromised networks for months or years before exfiltrating data, which means that when activity is detected the initial compromise may have occurred much earlier.

It adapts its tools and techniques rapidly after public reports from security researchers. When a tool is exposed the group abandons it and develops or adopts alternatives.

It uses living-off-the-land techniques extensively, using legitimate operating system tools such as PowerShell, WMI and certutil to reduce the presence of custom malware and make detection by signature-based security solutions more difficult.

---

## Emulation in this Lab

The emulation documented in this repository focuses on the most representative initial access and execution techniques of APT29 based on the MAD20 emulation plan and public MITRE ATT&CK reports.

The lab environment simulates a scenario where an administrative user receives and executes a malicious LNK file delivered via a spearphishing link, reflecting the attack vector documented in multiple real campaigns by the group.

Reference emulation plan: [MAD20 APT29 Emulation Plan](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/master/apt29)

---

## References and Further Reading

- [MITRE ATT&CK — APT29 Group](https://attack.mitre.org/groups/G0016/)
- [CISA — APT29 Targets COVID-19 Research](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a)
- [Microsoft — Midnight Blizzard](https://msrc.microsoft.com/blog/2024/01/microsoft-actions-following-attack-by-nation-state-actor-midnight-blizzard/)
- [Mandiant — APT29 Overview](https://www.mandiant.com/resources/apt29-domain-fronting-with-tls)
- [CrowdStrike — Cozy Bear](https://www.crowdstrike.com/adversaries/cozy-bear/)
- [NCSC UK — Advisory WellMess WellMail](https://www.ncsc.gov.uk/files/Advisory-APT29-targets-COVID-19-vaccine-development-V1-1.pdf)
- [Center for Threat Informed Defense — APT29 Emulation Plan](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/master/apt29)
