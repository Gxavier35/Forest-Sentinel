# 🛡️ ForestSentinel

O **ForestSentinel** é uma aplicação corporativa e multiplataforma (Windows/Linux) desenvolvida em Python. O sistema captura e analisa o tráfego de rede em tempo real, utilizando detecção por Inteligência Artificial (IA) sob um motor Scikit-Learn e um extrator de 38 features baseado nas especificações do CICFlowMeter, permitindo a identificação e bloqueio automático de ataques DoS e DDoS.

A aplicação conta com uma interface gráfica moderna e responsiva em PyQt6, oferecendo visualizações gráficas de fluxos de rede, configurações de perfis automatizados e gestão centralizada de Firewall.

---

## 🏗️ Arquitetura do Sistema

O projeto adota um design modular com múltiplos processos e threads para evitar gargalos (G.I.L) durante o processamento da captura em alta velocidade e avaliações dos frames, separando a carga pesada de inferência de rede da camada de apresentação da Interface Visual (UI).

- **Threads/Processos Principais:**
  - **Thread da UI:** Responsável por desenhar a tela, capturar eventos de usuário e apresentar KPIs (PyQt6 Main Thread).
  - **Processo de IA (Worker):** Orquestra o joblib para carga do pacote ML, lidando com inferência em lote (`batch`) sob um processo totalmente isolado (`multiprocessing`).
  - **Thread Sniffer:** Escuta a interface de rede crua injetando pacotes para classificação via Scapy.
  - **Thread Analisadora (`Analysis Loop`):** Compila o fluxo a partir dos raw-bytes para features (CICFlowMeter), submetendo as features computadas para predição via Inter-Process Communication (IPC Queues).

---

## 🗃️ Estrutura de Diretórios (Worktree)

```text
ddos_monitor/
├── assets/                  # Ícones, logotipos e sons (ex: alert.wav)
├── config/                  # Arquivos de configurações persistentes
│   ├── config.json          # Opções principais (autoblock, perfil, etc)
│   └── whitelist.txt        # Endereços IPs confiáveis
├── logs/                    # Destino dos logs de execução local (RotatingFile)
├── models/                  # Arquivos binários pré-treinados
│   ├── ddos_detection.pkl   # Modelo central treinado
│   └── scaler.pkl           # Scaler do pipeline ML
├── scripts/                 # Utilitários de setup extras
├── src/                     # Código fonte da aplicação
│   ├── main.py              # Entry-point e injeção (elevação de privilégio Win32)
│   ├── monitor_engine.py    # Orquestrador (Agrega flow, attack e models IPC)
│   ├── dashboard.py         # Janela Principal do sistema
│   ├── flow_manager.py      # Gestão de estados de fluxo e batch throttling
│   ├── attack_manager.py    # Temporalidade de ataques, whitelisting.
│   ├── firewall.py          # Wrapper Multi-OS (netsh, iptables, nftables)
│   ├── features.py          # Matemática de features dos pacotes em janelas.
│   ├── config_manager.py    # Helper I/O da configuração
│   ├── constants.py         # Configs hardcoded, DataClasses e Enum de Status
│   ├── ui_components.py     # Widgets granulares (Gráficos, Cards, Banners)
│   ├── ui_tabs.py           # Abas principais (Operação, Configurações)
│   └── utils.py             # Funções utilitárias e pathing.
└── requirements.txt         # Pacotes estritos para o projeto.
```

---

## ⚙️ Componentes Principais (Core Features)

### 1. `monitor_engine.py` (Engine Orquestradora)
Representa o núcleo observável da aplicação (`QObject`). Coordena a sincronização de IPC, inicialização do `FlowManager` e propagação de sinais de rede em direção a Interface. Ele contém a lógica do Watchdog IA que reinicia o processo isolado caso ele falhe sob estresse.

### 2. `flow_manager.py` (Gerenciador de Fluxos)
Armazena a contagem dos dados transferidos categorizando fluxos raw (`scapy`). Responsável por manter históricos (`deque`) de envio e processamento otimizando as verificações cíclicas e promovendo *Eviction* rápido em memória das conexões obsoletas. 

### 3. `features.py` (Feature Extraction Pipeline & CICFlowMeter)
**O que é o CICFlowMeter?** 
O CICFlowMeter (anteriormente conhecido como ISCXFlowMeter) é um motor de extração de tráfego computacional criado pelo Instituto Canadense de Cibersegurança (UNB). Em vez de focar intensamente no payload (conteúdo cru da conversa), ele extrai os sinais de comportamento, medindo como uma conexão se porta matematicamente no tempo e quantidade. É o extrator responsável por gerar bases fundamentais famosas na comunidade de cibersegurança global, como o CICIDS2017 e CICDDoS2019.

Nesse software, o `features.py` não depende de utilitários externos lentos ou de arquivos CSV off-line, ele **reimplementou parte desse extrator para funcionar em tempo real na memória**. O motor Python varre em janela as mesmas matrizes exigidas pelos estudos e extrai **38 features primárias** idênticas ao padrão UNB para injetar no processo dedutivo (Machine Learning):
- Contagem e Frequência de Bytes, Pacotes, Duração e Throughput (B/s, P/s).
- Matemática Estatística sobre assinaturas das Flags TCP (FIN, SYN, RST, PSH, ACK, URG, etc).
- Análise de IAT - Inter-Arrival Times (Fwd e Bwd). 
- Análise pesada de comportamentos contínuos ou em "Bulk".

### 4. `attack_manager.py` (Sistema de Resposta Sensível / Temporizadores de Alerta)
Aplica lógicas temporais rígidas (debounces) com o intuito de distinguir falsos positivos do tráfego transiente comum para um efetivo ataque continuado contra à rede.

**Processo de Escalada de Ameaça (Thresholds e Tempos):**
Para mitigar os riscos de indisponibilizar a rede indevidamente, o bloqueio do Monitor não é instintivo no primeiro pacote maldoso flagrado. Ele opera sob o julgamento persistente configurado em `constants.py`:
- **Level 1 (30 Segundos):** Se a Inteligência Artificial acusar anomalias por 30s consecutivos para um mesmo fluxo espelho, a UI acenderá a classificação transitória de *POSSÍVEL ATAQUE* (`SUSPICIOUS` — Amarelo). 
- **Level 2 (60 Segundos):** Sob continuação direta do estresse após atingir a casa dos 60 segundos, consolida publicamente a ameaça para *ATAQUE CONFIRMADO* (`ATTACK` — Vermelho). 
- **Auto-Block (90 Segundos / 1m30s):** O tempo de persistência mínima para que uma ofensa madura dispare os *Hooks* no seu Firewall. Chegou nesse limiar temporal? A interface local delega a eliminação silenciosa dessa conexão via Host.

Isso também garante a flexibilização reversa (Normalização). Endereços paralisados que se limparam recuperam seu Score automaticamente, perdoados pela "latência cíclica" estipulada. Lida também com intersecções explícitas de redes na base paralela imutável (Whitelist). 

### 5. `firewall.py` (Abstração Windows & Linux) 
Forte foco de automação e injeção de segurança no Host Base Firewall. 
- **Windows:** Utilitários via `netsh advfirewall`
- **Linux:** Detecção heurística entre `iptables` ou preferencialmente, o `nftables` abstraindo Chains locais restritas para blackholing. 

---

## ⚡ Engenharia de Alta Performance (Resiliência sob Estresse)

Diferente de scripts acadêmicos padrão, este Monitor foi engenheirado para **sobreviver a ataques volumétricos massivos** sem esgotar a RAM do hospedeiro ou congelar a interface. Para isso, 3 tecnologias de resiliência funcionam ativamente nos bastidores:

1. **Watchdog IA de Prevenção de Falhas (`monitor_engine.py`)**: O motor de Inteligência Artificial opera como um "Worker Process" completamente isolado da thread geral via `multiprocessing`. Caso um fluxo cause um estouro de memória ou corrompa o Worker, o *Watchdog* instanciado na Engine recarrega o modelo de predição automaticamente em instantes, garantindo que o _Network Sniffer_ não engasgue ou perca amostras de pacotes cruciais durante o apagão temporal.
2. **Throttling Temporizado em Batch (`MAX_ANALYZE_PER_SEC`)**: Para que a CPU não atinja um uso nocivo validando requisições diminutas por segundo, o motor aplica a chave (com padrão base de 300 avaliações matemáticas profundas permitidas por segundo). Fluxos gigantes entram em uma lista que prioriza os que transferiram mais pacotes, processando as predições em lote inter-process.
3. **Eviction Anti-OOM (Out Of Memory) (`flow_manager.py`)**: A classe responsável por agrupar as flags de conexão previne inundações de Denial of Service com um teto restritivo (`MAX_FLOWS = 5000`). Em um cataclismo onde IPs forcem a estourar a memória preenchendo as chaves do dicionário, o algoritmo realiza uma auto-limpeza *(Eviction)* extirpando brutalmente os 50 registros de fluxos mais antigos da RAM para resgatar o monitor, focando memória para absorver ataques persistentes correntes sem latência.

---

## 🧠 Operações da Inteligência Artificial

O Motor carrega um pipeline ML salvo via Joblib. Por eficiência e segurança de lock (GIL), esse processo executa sob `multiprocessing`. Os perfis IA (`Home`, `Pme`, `Datacenter`) representam thresholds modificados sob a `decision_function`, permitindo ajustar o compromisso sobre detecções severas e limiares brandos nas predições de um modelo isolado floresta aleatória (ou SVM) estático. 

- **Configurações Padrões:**
  - *Datacenter:* `0.00`
  - *PME (SMB):* `-0.15`
  - *Home (Casa/Doméstico):* `-0.30`

Esses cortes representam a flexibilidade preditiva contra os fluxos identificados (Suspeito para Total Bloqueio).

---

## 🛠 Requisitos de Sistema

- Python \>= 3.9
- **Npcap (Bibliotecas Wireshark)** ou WinPcap [Obrigatório no Windows]
- Dependências da lista (incluindo dependências compiladas e QT).
- Privilégios elevados (`Root` / `Sudo` / `Administrador (UAC)`) 

### Instalação

```bash
# 1. Clone ou baixe o projeto.
git clone <repository_url>

# 2. Instale as dependências usando pip
pip install -r requirements.txt

# Obs: Verifique a instalação do Npcap no Windows se for capturar sob adaptadores baseados em loops (localhost/WiFi)!
```

---

## 🚀 Como Executar

Apenas execute o entry-point (`main.py`). Se executado via Shell padrão no Windows localmente ele forçará elevação do privilégio (`UAC prompt`) e se passará como uma Window limpa GUI.

```bash
cd ddos_monitor
python src/main.py
```

### Funcionalidade Operacional e de Interface
Uma vez ativado, a interface possuirá um monitor ao vivo (Dashboard) e abas de configurações:
- **Monitor:** Visualiza os TOP ~50 Fluxos simultâneos mais agressivos, e suas estatísticas macroscópicas.
- **Config:** Liga modo Autoblock e Modela limiares da IA e Rede Escutada.
- **Bloqueados:** Representa graficamente quem compõe `ddos_monitor` (No Linux) ou `DDoS_Block_*` (No netsh) podendo Desbloquear.
- **Whitelist:** Regras imutáveis que previnem o bloqueio até mesmo se a Inteligência interpor. 

---

## 🛡️ Segurança Crítica - Proteções de Comando Injetado

A Abstração do Gerenciador de firewall previne explorações sobre a Shell contra endereços injetados ou capturados por Sniffers. Tudo passa pelo validador interno `ipaddress.ip_address` limitando-se apenas ao processamento legal entre as conversões base e o SO.

---

## 📦 Geração do Executável e Instalador (Windows)

Para transformar o código Python em um executável profissional e gerar o instalador `.exe`, siga os passos abaixo:

### 1. Requisitos de Build
Certifique-se de ter as dependências de desenvolvimento instaladas:
```bash
pip install pyinstaller
```

### 2. Gerar a pasta do Executável (PyInstaller)
Utilize o arquivo `.spec` fornecido para garantir que todas as dependências e pastas de dados (`assets`, `models`, `config`) sejam incluídas:
```bash
pyinstaller ForestSentinel.spec --noconfirm
```
Isso gerará a pasta `dist/ForestSentinel` contendo todos os arquivos necessários.

### 3. Criar o Instalador Final (Inno Setup)
O projeto utiliza o **Inno Setup** para compilar o diretório `dist` em um único arquivo de instalação profissional.
1. Abra o arquivo `installer.iss` no **Inno Setup Compiler**.
2. Clique em **Build > Compile (F9)**.
3. O instalador final será gerado na pasta **`Instalador/`** com o nome `ForestSentinel_Setup_v1.1.1.exe`.

### 4. Automação via Script
Você pode usar o script automatizado para realizar o build do PyInstaller e limpar arquivos temporários:
```powershell
.\scripts\build_installer.bat
```

---

## 📄 Licença e Uso

Este software é fornecido para fins de monitoramento e segurança de rede. O uso indevido para atividades ilícitas é de total responsabilidade do utilizador.
