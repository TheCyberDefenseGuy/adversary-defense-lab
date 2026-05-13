# APT29 — Cozy Bear

> Perfil completo do grupo de ameaça APT29, também conhecido como Cozy Bear, com histórico de campanhas reais, alvos, TTPs mais utilizados e contexto geopolítico.

---

## Identificação

| Atributo | Detalhe |
|---|---|
| Nome | APT29 |
| Aliases | Cozy Bear, The Dukes, Midnight Blizzard, NOBELIUM, Dark Halo |
| Origem | Rússia |
| Patrocinador | SVR — Serviço de Inteligência Estrangeira da Rússia |
| Activo desde | 2008 |
| Motivação | Espionagem política, económica e militar |
| Alvos principais | Governos, think tanks, ONGs, empresas de tecnologia, saúde e energia |

---

## Contexto

O APT29 é um dos grupos de ameaça persistente avançada mais sofisticados e activos do mundo. Opera sob o controlo do SVR russo e tem como missão principal a recolha de inteligência estratégica para apoiar os interesses do estado russo. Ao contrário de grupos com motivação financeira, o APT29 foca-se em operações de longa duração onde a persistência e o sigilo têm mais valor do que o impacto imediato.

O grupo é conhecido por desenvolver as suas próprias ferramentas, adaptar as suas técnicas rapidamente após exposição pública e utilizar infraestrutura legítima como cloud services e plataformas conhecidas para mascarar as suas comunicações C2.

---

## Campanhas Conhecidas

### SolarWinds — SUNBURST (2020)

A campanha mais impactante do APT29 foi a comprometimento da cadeia de fornecimento da SolarWinds. O grupo injectou código malicioso no software Orion da SolarWinds que foi distribuído como uma actualização legítima para cerca de 18.000 organizações incluindo múltiplas agências do governo americano como o Departamento de Estado, o Tesouro e o Departamento de Segurança Interna.

O ataque permaneceu não detectado durante aproximadamente 9 meses e é considerado uma das operações de espionagem cibernética mais sofisticadas já documentadas.

Referência: [CISA Alert AA20-352A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a)

### Hack do Comité Nacional Democrata (2016)

O APT29 comprometeu os sistemas do DNC em conjunto com o APT28 durante as eleições presidenciais americanas de 2016. O grupo manteve acesso silencioso durante meses enquanto recolhia emails e documentos internos.

Referência: [CrowdStrike Report — Bears in the Midst](https://www.crowdstrike.com/blog/bears-midst-intrusion-democratic-national-committee/)

### COVID-19 Research Targeting (2020)

Durante a pandemia o APT29 conduziu campanhas de spearphishing contra organizações de investigação de vacinas no Reino Unido, Canadá e Estados Unidos. O NCSC britânico, o CSE canadiano e a NSA americana publicaram um aviso conjunto identificando o grupo.

Referência: [NCSC Advisory — APT29 targets COVID-19 vaccine research](https://www.ncsc.gov.uk/news/advisory-apt29-targets-covid-19-vaccine-research)

### Microsoft e Outras Empresas de Tecnologia (2023-2024)

O grupo comprometeu contas de email executivas da Microsoft através de password spray e acesso a aplicações OAuth legacy. A Microsoft identificou o grupo como Midnight Blizzard e reportou que o acesso inicial ocorreu em Novembro de 2023 e foi descoberto em Janeiro de 2024.

Referência: [Microsoft Security Blog — Midnight Blizzard](https://msrc.microsoft.com/blog/2024/01/microsoft-actions-following-attack-by-nation-state-actor-midnight-blizzard/)

### TeamViewer (2024)

O APT29 comprometeu sistemas internos da TeamViewer usando credenciais de uma conta de empregado. A empresa confirmou o incidente em Junho de 2024.

---

## TTPs Mais Utilizados

O APT29 utiliza um conjunto consistente de técnicas ao longo das suas campanhas. A tabela abaixo mostra os TTPs mais frequentes mapeados no MITRE ATT&CK.

| TTP | Técnica | Táctica |
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

Referência completa: [MITRE ATT&CK — APT29](https://attack.mitre.org/groups/G0016/)

---

## Ferramentas e Malware Associados

| Ferramenta | Tipo | Descrição |
|---|---|---|
| SUNBURST | Backdoor | Injectado na cadeia de fornecimento da SolarWinds |
| SUNSHUTTLE | Backdoor | Segunda fase após SUNBURST |
| TEARDROP | Loader | Carrega o Cobalt Strike em memória |
| MiniDuke | Backdoor | Usado em campanhas contra governos europeus |
| CosmicDuke | Infostealer | Recolha de credenciais e documentos |
| WellMess | RAT | Usado nas campanhas contra investigação COVID-19 |
| WellMail | RAT | Variante do WellMess |
| Cobalt Strike | Framework | Usado extensivamente para C2 pós-comprometimento |

---

## Infra-estrutura e C2

O APT29 é conhecido por utilizar infraestrutura legítima para mascarar as suas comunicações e dificultar a atribuição e o bloqueio. Entre as técnicas documentadas estão o uso de serviços cloud legítimos como OneDrive, Dropbox e Google Drive como canais C2, o registo de domínios que imitam serviços legítimos como actualizações de software, o uso de certificados TLS válidos para HTTPS em comunicações C2 e a rotação frequente de infraestrutura após exposição.

---

## Características Distintivas

O APT29 distingue-se de outros grupos APT por várias características que tornam a sua detecção e atribuição particularmente difíceis.

O grupo tem uma paciência operacional excepcional e mantém acesso a redes comprometidas durante meses ou anos antes de exfiltrar dados, o que significa que quando a actividade é detectada o comprometimento inicial pode ter ocorrido muito antes.

Adapta as suas ferramentas e técnicas rapidamente após relatórios públicos de investigadores de segurança. Quando uma ferramenta é exposta o grupo abandona-a e desenvolve ou adopta alternativas.

Utiliza técnicas de living-off-the-land extensivamente, usando ferramentas legítimas do sistema operativo como PowerShell, WMI e certutil para reduzir a presença de malware customizado e dificultar a detecção por soluções de segurança baseadas em assinaturas.

---

## Emulação neste Lab

A emulação documentada neste repositório foca-se nas técnicas de acesso inicial e execução mais representativas do APT29 baseadas no plano de emulação MAD20 e nos relatórios públicos do MITRE ATT&CK.

O ambiente de laboratório simula um cenário onde um utilizador administrativo recebe e executa um ficheiro LNK malicioso entregue via link de spearphishing, reflectindo o vector de ataque documentado em múltiplas campanhas reais do grupo.

Plano de emulação de referência: [MAD20 APT29 Emulation Plan](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/master/apt29)

---

## Referências e Leitura Adicional

- [MITRE ATT&CK — APT29 Group](https://attack.mitre.org/groups/G0016/)
- [CISA — APT29 Targets COVID-19 Research](https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a)
- [Microsoft — Midnight Blizzard](https://msrc.microsoft.com/blog/2024/01/microsoft-actions-following-attack-by-nation-state-actor-midnight-blizzard/)
- [Mandiant — APT29 Overview](https://www.mandiant.com/resources/apt29-domain-fronting-with-tls)
- [CrowdStrike — Cozy Bear](https://www.crowdstrike.com/adversaries/cozy-bear/)
- [NCSC UK — Advisory WellMess WellMail](https://www.ncsc.gov.uk/files/Advisory-APT29-targets-COVID-19-vaccine-development-V1-1.pdf)
- [Center for Threat Informed Defense — APT29 Emulation Plan](https://github.com/center-for-threat-informed-defense/adversary_emulation_library/tree/master/apt29)
