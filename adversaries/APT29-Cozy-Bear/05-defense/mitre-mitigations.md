# Mitigações MITRE ATT&CK — APT29

Para cada TTP emulado neste laboratório são documentadas as mitigações recomendadas pelo MITRE ATT&CK. As mitigações estão organizadas por fase do ataque seguindo a sequência real da emulação.

---

## Fase 1 — Initial Access

### T1566.002 — Spearphishing Link

O APT29 entrega o payload através de um link malicioso que força o download de um ficheiro LNK via browser.

**M1054 — Software Configuration**
Configura o browser para bloquear o download automático de tipos de ficheiros perigosos como LNK, EXE e SCR. No Microsoft Edge activa o SmartScreen e configura políticas de download restritivas.
[https://attack.mitre.org/mitigations/M1054/](https://attack.mitre.org/mitigations/M1054/)

**M1017 — User Training**
Treina utilizadores para reconhecer emails de spearphishing e não clicar em links ou abrir ficheiros de fontes não verificadas. Simulações regulares de phishing aumentam significativamente a resistência.
[https://attack.mitre.org/mitigations/M1017/](https://attack.mitre.org/mitigations/M1017/)

**M1021 — Restrict Web-Based Content**
Usa web proxies e filtros de URL para bloquear acesso a domínios maliciosos conhecidos e categorias de sites de alto risco.
[https://attack.mitre.org/mitigations/M1021/](https://attack.mitre.org/mitigations/M1021/)

---

### T1204.002 — Malicious File (LNK)

O utilizador executa o ficheiro LNK que contém um comando PowerShell escondido.

**M1038 — Execution Prevention**
Usa AppLocker ou Windows Defender Application Control para bloquear a execução de ficheiros LNK a partir de pastas de download e temp.
[https://attack.mitre.org/mitigations/M1038/](https://attack.mitre.org/mitigations/M1038/)

**M1017 — User Training**
Treina utilizadores para não abrir ficheiros descarregados sem verificação prévia, especialmente ficheiros com ícones de PDF ou documentos que sejam na realidade shortcuts LNK.
[https://attack.mitre.org/mitigations/M1017/](https://attack.mitre.org/mitigations/M1017/)

---

## Fase 2 — Execution e Command and Control

### T1059.001 — PowerShell Execution

O APT29 usa PowerShell para executar payloads e estabelecer o C2.

**M1045 — Code Signing**
Configura a PowerShell Execution Policy para AllSigned ou RemoteSigned, exigindo que scripts sejam assinados digitalmente por uma entidade de confiança.
[https://attack.mitre.org/mitigations/M1045/](https://attack.mitre.org/mitigations/M1045/)

**M1042 — Disable or Remove Feature or Program**
Onde o PowerShell não é necessário para utilizadores finais, desactiva-o ou restringe o acesso via Group Policy. Para utilizadores que precisam de PowerShell usa Constrained Language Mode.
[https://attack.mitre.org/mitigations/M1042/](https://attack.mitre.org/mitigations/M1042/)

**M1026 — Privileged Account Management**
Restringe quais contas podem executar PowerShell com privilégios elevados. Utilizadores standard não devem ter acesso a PowerShell administrativo.
[https://attack.mitre.org/mitigations/M1026/](https://attack.mitre.org/mitigations/M1026/)

---

### T1027 — Obfuscation

O APT29 ofusca os payloads com Base64 e -ExecutionPolicy Bypass para evadir detecção.

**M1049 — Antivirus/Antimalware**
Activa o AMSI (Antimalware Scan Interface) que intercepta scripts PowerShell decodificados antes da execução, mesmo quando ofuscados com Base64 ou outras técnicas.
[https://attack.mitre.org/mitigations/M1049/](https://attack.mitre.org/mitigations/M1049/)

**M1040 — Behavior Prevention on Endpoint**
Usa EDR com detecção comportamental para identificar padrões de ofuscação mesmo quando as assinaturas estáticas não detectam.
[https://attack.mitre.org/mitigations/M1040/](https://attack.mitre.org/mitigations/M1040/)

---

### T1218.011 — Rundll32

O APT29 usa Rundll32 para carregar DLLs maliciosas e evadir controlos que bloqueiam apenas executáveis.

**M1050 — Exploit Protection**
Configura Windows Defender Exploit Guard para aplicar protecções adicionais ao rundll32.exe, incluindo bloqueio de chamadas Win32k e prevenção de injecção de código.
[https://attack.mitre.org/mitigations/M1050/](https://attack.mitre.org/mitigations/M1050/)

**M1038 — Execution Prevention**
Usa AppLocker ou WDAC para bloquear a execução de DLLs não assinadas via rundll32, permitindo apenas DLLs de paths autorizados.
[https://attack.mitre.org/mitigations/M1038/](https://attack.mitre.org/mitigations/M1038/)

---

### T1071.001 — C2 via HTTPS

O APT29 usa HTTPS na porta 443 para mascarar as comunicações C2 como tráfego legítimo.

**M1031 — Network Intrusion Prevention**
Implementa TLS inspection no proxy de saída para inspeccionar tráfego HTTPS e detectar comunicações C2 mesmo em canais cifrados.
[https://attack.mitre.org/mitigations/M1031/](https://attack.mitre.org/mitigations/M1031/)

**M1037 — Filter Network Traffic**
Restringe o tráfego de saída a destinos conhecidos e autorizados. Endpoints não devem estabelecer ligações HTTPS directas a IPs arbitrários sem passar por um proxy.
[https://attack.mitre.org/mitigations/M1037/](https://attack.mitre.org/mitigations/M1037/)

---

## Fase 3 — Discovery

### T1087 — Account Discovery
### T1069 — Permission Groups Discovery
### T1082 — System Information Discovery
### T1057 — Process Discovery
### T1012 — Registry Query

O APT29 usa ferramentas nativas do Windows como net, systeminfo, tasklist e reg para mapear o ambiente sem instalar ferramentas adicionais (living off the land).

**M1028 — Operating System Configuration**
Audita e restringe quem pode executar comandos de enumeração. Utilizadores standard não devem ter acesso a net.exe para consultas de domínio.
[https://attack.mitre.org/mitigations/M1028/](https://attack.mitre.org/mitigations/M1028/)

**M1026 — Privileged Account Management**
Implementa o princípio do mínimo privilégio. Contas de serviço e utilizadores normais não devem ter permissões de Domain User que permitem enumeração extensiva do AD.
[https://attack.mitre.org/mitigations/M1026/](https://attack.mitre.org/mitigations/M1026/)

**M1018 — User Account Management**
Revê e remove permissões excessivas em contas como svc.backup que não devem ter acesso a ferramentas de administração.
[https://attack.mitre.org/mitigations/M1018/](https://attack.mitre.org/mitigations/M1018/)

---

## Fase 4 — Collection e Persistence

### T1560 — Archive Collected Data

O APT29 usa 7-Zip para comprimir dados antes da exfiltração.

**M1057 — Data Loss Prevention**
Implementa DLP para detectar e bloquear a criação de arquivos ZIP em paths suspeitos ou fora das pastas de trabalho autorizadas.
[https://attack.mitre.org/mitigations/M1057/](https://attack.mitre.org/mitigations/M1057/)

**M1041 — Encrypt Sensitive Information**
Cifra dados sensíveis em repouso para que mesmo que sejam comprimidos e exfiltrados não sejam legíveis sem a chave de decifração.
[https://attack.mitre.org/mitigations/M1041/](https://attack.mitre.org/mitigations/M1041/)

---

### T1105 — Ingress Tool Transfer

O APT29 usa Invoke-WebRequest para descarregar ferramentas adicionais para o sistema comprometido.

**M1031 — Network Intrusion Prevention**
Bloqueia downloads de executáveis e DLLs a partir de IPs não autorizados. O tráfego de saída deve passar por proxy com inspeção de conteúdo.
[https://attack.mitre.org/mitigations/M1031/](https://attack.mitre.org/mitigations/M1031/)

**M1037 — Filter Network Traffic**
Restringe quais processos podem fazer chamadas de rede de saída. powershell.exe não deve poder descarregar ficheiros directamente da internet sem passar por proxy.
[https://attack.mitre.org/mitigations/M1037/](https://attack.mitre.org/mitigations/M1037/)

---

### T1547.009 — Startup Folder Persistence

O APT29 copia o payload LNK para a pasta Startup para garantir execução no próximo login.

**M1022 — Restrict File and Directory Permissions**
Remove permissões de escrita na pasta Startup para utilizadores não administradores. Apenas processos elevados devem poder escrever nesta localização.
[https://attack.mitre.org/mitigations/M1022/](https://attack.mitre.org/mitigations/M1022/)

**M1024 — Restrict Registry Permissions**
Para persistência via registry (variante T1547.001), restringe permissões nas chaves Run e RunOnce a administradores.
[https://attack.mitre.org/mitigations/M1024/](https://attack.mitre.org/mitigations/M1024/)

---

## Resumo das Mitigações por TTP

| TTP | Técnica | Mitigação Principal | ID MITRE |
|---|---|---|---|
| T1566.002 | Spearphishing Link | Software Configuration + User Training | M1054, M1017 |
| T1204.002 | Malicious File LNK | Execution Prevention | M1038 |
| T1059.001 | PowerShell Execution | Code Signing + Disable Feature | M1045, M1042 |
| T1027 | Obfuscation | Antivirus/AMSI | M1049 |
| T1218.011 | Rundll32 | Exploit Protection + Execution Prevention | M1050, M1038 |
| T1071.001 | C2 HTTPS | Network Intrusion Prevention | M1031 |
| T1087 | Account Discovery | OS Configuration + Least Privilege | M1028, M1026 |
| T1069 | Permission Groups | Privileged Account Management | M1026 |
| T1082 | System Info | OS Configuration | M1028 |
| T1057 | Process Discovery | OS Configuration | M1028 |
| T1012 | Registry Query | OS Configuration | M1028 |
| T1560 | Archive Data | Data Loss Prevention | M1057 |
| T1105 | Tool Transfer | Network Intrusion Prevention | M1031 |
| T1547.009 | Startup Persistence | Restrict File Permissions | M1022 |

---

## Referências

- [MITRE ATT&CK — APT29](https://attack.mitre.org/groups/G0016/)
- [MITRE ATT&CK — Mitigations](https://attack.mitre.org/mitigations/enterprise/)
- [CISA — APT29 Advisory](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a)
- [Microsoft — Protect against APT29](https://www.microsoft.com/en-us/security/blog/2024/01/25/midnight-blizzard-guidance-for-responders-on-nation-state-attack/)
