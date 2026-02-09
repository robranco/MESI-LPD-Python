# Guia de Execução do Menu MESI-LPD

Este repositório reúne os scripts acionados pelos menus `26716-LPD-python-menu-principal.py` e `26716-LPD-python-menu-principal-auth.py`. O objetivo deste documento é permitir que qualquer pessoa que clone o projeto configure rapidamente o ambiente, entenda o propósito de cada opção e execute os utilitários sem adivinhações.

## Ambiente suportado
- Os scripts foram validados em Linux e em WSL (Windows Subsystem for Linux). Python para Windows **pode** funcionar, mas não há suporte oficial.
- Todos os comandos abaixo presumem um shell Bash dentro do Linux/WSL.

## Preparação do ambiente (.venv)
1. Instale os pacotes de sistema necessários:
	```bash
	sudo apt update
	sudo apt install -y python3 python3-venv python3-pip python3-dev build-essential \
		 sshpass netcat-openbsd awk gzip
	```
	- Para os scripts de GeoIP, deixe os arquivos `GeoLite2-City.mmdb` e `GeoLite2-Country.mmdb` dentro da pasta `maxmind/` (já provida no projeto).
2. Crie e ative o ambiente virtual:
	```bash
	python3 -m venv .venv
	source .venv/bin/activate
	python -m pip install --upgrade pip
	```
3. Instale as dependências Python usadas pelos menus:
	```bash
	pip install -r requirements.txt
	```
4. Sempre que abrir um novo terminal, volte a ativar o `.venv` com `source .venv/bin/activate`.

### Requisitos adicionais por script
- `sshpass`, `ssh`/`scp` e privilégios de `sudo` remoto: necessários para `26716-LPD-python-LOGs-buscar-log-remoto.py`.
- `netcat-openbsd` (comando `nc`): usado por `26716-LPD-python-port-knocking-client.py`.
- Permissão de envio de pacotes RAW (sudo ou execução como root): obrigatória para `26716-LPD-python-SYN-flood-target.py` (Scapy).
- Bases MaxMind: todos os analisadores de log precisam dos arquivos dentro de `maxmind/`.

## Arquivos de suporte essenciais
- `26716-LPD-python-menus-opcoes.csv`: define o texto e o script de cada opção dos menus.
- `26716-LPD-python-credentials.txt`: arquivo CSV simples (hash do usuário + hash da senha) usado por `menu-principal-auth`. Gere-o com o script auxiliar `26716-LPD-python-create-credentials.py` ou edite manualmente.
- `regular-expression-awk-ip-address-and-timestamp.awk`: AWK responsável por extrair IP e timestamp a partir dos logs.
- `maxmind/GeoLite2-*.mmdb`: bases GeoLite utilizadas pelos scripts com geolocalização.
- `reports/`: destino padrão para CSV, HTML, PDF e bases SQLite geradas.
- `baixados/`: pasta sugerida pelo coletor remoto para armazenar logs copiados via SSH.
- `IPbeja_horizontal.png` e `IPBeja_estig_horizontal.png`: logos incorporados no relatório PDF.
- `not-used/`: guarda arquivos que não são chamados pelos menus (referência histórica).

## Executando os menus
> Sempre que um dos menus é iniciado, o terminal exibe automaticamente o lembrete:
> `python3 -m venv .venv`, `source .venv/bin/activate` e `pip install -r requirements.txt.`

1. Ative o `.venv`.
2. Para o menu simples:
	```bash
	python 26716-LPD-python-menu-principal.py
	```
3. Para o menu com autenticação (usa hashes SHA-512):
	```bash
	python 26716-LPD-python-menu-principal-auth.py
	```
	- Insira o usuário e a senha cadastrados em `26716-LPD-python-credentials.txt`.
4. Escolha a opção desejada e informe os parâmetros solicitados pelo script correspondente.

## Scripts disponíveis no menu
Cada item abaixo descreve o mesmo número da coluna `numero` do CSV do menu.

### 1. 26716-LPD-python-port(s)-scan-target(s).py
- **Objetivo:** varrer portas TCP em uma ou várias máquinas para identificar serviços abertos rapidamente.
- **Uso:** informe uma lista de hosts (IP ou DNS) separados por vírgula e, opcionalmente, uma lista de portas. Caso não forneça portas, o script usa um conjunto padrão (22, 80, 443, 3389 etc.). O resultado é impresso no terminal, indicando “ABERTA” ou “fechada”.
- **Dependências específicas:** apenas a biblioteca padrão do Python.

### 2. 26716-LPD-python-UDP-flood-target.py
- **Objetivo:** demonstrar o envio intensivo de pacotes UDP para testar resiliência (uso estritamente educacional em redes controladas).
- **Uso:** informe o endereço do alvo e o tempo de execução em segundos (padrão 10). O script envia datagramas para todas as portas e mostra o contador de pacotes enviados.
- **Dependências específicas:** biblioteca padrão; recomenda-se executar em ambiente isolado.

### 3. 26716-LPD-python-SYN-flood-target.py
- **Objetivo:** gerar tráfego SYN (Scapy) para avaliar proteção contra flood.
- **Uso:** execute como root ou via `sudo`, informe o alvo, a porta de destino (padrão 80) e a duração. O script envia SYNs com portas de origem aleatórias e mostra o total transmitido.
- **Dependências específicas:** `scapy` (pip) e permissão para pacotes RAW.

### 4. 26716-LPD-python-LOGs-buscar-log-remoto.py
- **Objetivo:** copiar um arquivo de log remoto que exige `sudo`, comprimir, validar SHA-256 e salvar localmente.
- **Uso:** informe servidor, usuário, caminho do log e senha (utilizada para SSH e sudo). O script gera arquivos temporários no host remoto, baixa o `.gz` e o `.sha256sum.txt` via `scp`, valida e extrai o conteúdo para `baixados/AAAA-MM-DD-HH-MM-servidor-caminho.log`.
- **Dependências específicas:** utilitário `sshpass`, comandos `ssh`/`scp`, gzip no destino remoto e local.

### 5. 26716-LPD-python-LOGs-http-ssh-e-ufw.py
- **Objetivo:** resumir origens de acessos HTTP/SSH/UFW agrupadas por país.
- **Uso:** informe o caminho do log (padrão `/var/log/apache2/access.log`). O script chama o AWK auxiliar, resolve país/cidade via GeoLite e gera `reports/<log>_relatorio_http_ssh_ufw.txt`.
- **Dependências específicas:** `geoip2`, AWK auxiliar e bases `GeoLite2`.

### 6. 26716-LPD-python-LOGs-http-ssh-e-ufw.csv.py
- **Objetivo:** mesma extração da opção 5, mas salva um CSV cronológico.
- **Uso:** após informar o log, o script gera arquivos `reports/26716-<timestamp>-<origem>-<nome>.csv` prontos para planilhas.
- **Dependências específicas:** `geoip2`, AWK e bases `GeoLite2`.

### 7. 26716-LPD-python-LOGs-http-ssh-e-ufw.pdf.py
- **Objetivo:** criar um relatório PDF com contagens por país/cidade/IP, incluindo logos institucionais.
- **Uso:** informe o arquivo de log. O programa calcula métricas, adiciona logos `IPbeja_horizontal.png` e `IPBeja_estig_horizontal.png` (se presentes) e grava `reports/26716-...pdf`.
- **Dependências específicas:** `geoip2`, `reportlab`, AWK auxiliar, bases `GeoLite2` e os arquivos de logo.

### 8. 26716-LPD-python-LOGs-http-ssh-e-ufw.SQLite.py
- **Objetivo:** carregar IP/timestamp/cidade/país em uma base SQLite simples.
- **Uso:** semelhante às opções anteriores, porém gera `reports/26716-...sqlite` contendo uma tabela `acessos` limpa a cada execução.
- **Dependências específicas:** `geoip2`, AWK auxiliar, bases `GeoLite2` e `sqlite3` (padrão).

### 9. 26716-LPD-python-port-knocking-client.py
- **Objetivo:** enviar a sequência de knock nas portas 4444, 3333 e 2222 para liberar SSH em firewalls que exigem esse fluxo.
- **Uso:** indique o host (padrão 192.168.1.105) e o usuário. O script usa `nc` para abrir/fechar rapidamente cada porta e, ao final, orienta a executar `ssh usuario@host`.
- **Dependências específicas:** comando `nc` (netcat-openbsd).

### 10. 26716-LPD-python-LOGs-http-ssh-e-ufw-folium-country-map.py
- **Objetivo:** gerar CSV e mapa HTML (Folium) mostrando volume de acessos por país.
- **Uso:** informe o log, valide o resumo no terminal e abra `reports/<log>_acessos_por_pais.html` para visualizar o mapa. Também é salvo `reports/<log>_acessos_por_pais.csv`.
- **Dependências específicas:** `geoip2`, `folium`, AWK auxiliar, bases `GeoLite2`.

### 11. 26716-LPD-python-LOGs-http-ssh-e-ufw-folium-city-map.py
- **Objetivo:** mapa HTML por cidade, adicionando contagens e CSV completos.
- **Uso:** semelhante à opção 10; gera `reports/<log>_acessos_por_cidade.csv` e `reports/<log>_acessos_por_cidade.html` com marcadores médios.
- **Dependências específicas:** `geoip2`, `folium`, AWK auxiliar, bases `GeoLite2`.

### 12. 26716-LPD-python-LOGs-http-ssh-e-ufw-stats-IPv4-IPv6.py
- **Objetivo:** sumarizar logs destacando totais IPv4/IPv6, percentuais, primeiros/últimos eventos e proporção de IPs únicos.
- **Uso:** informe o log. O script cria um relatório texto (`reports/<log>_relatorio_http_ssh_ufw-stats-IPv4-IPv6.txt`) e um HTML com quatro gráficos desenhados em `<canvas>`.
- **Dependências específicas:** somente bibliotecas padrão (`ipaddress`, `json` etc.) além do AWK auxiliar.

### 13. 26716-LPD-python-LOGs-http-ssh-e-ufw.SQLite-cifrado.py
- **Objetivo:** gravar os campos de log em SQLite com cifragem AES-256 (modo GCM) por campo.
- **Uso:** o script solicita a senha da cifragem antes de perguntar pelo log. Gera `reports/26716-...-cifrado-AES-256.sqlite`. Use a mesma senha depois ao decifrar.
- **Dependências específicas:** `geoip2`, `pycryptodome`, AWK auxiliar, bases `GeoLite2`.

### 14. 26716-LPD-python-LOGs-http-ssh-e-ufw.SQLite-decifrar.py
- **Objetivo:** ler a base cifrada da opção 13 e exibir os registros em texto puro.
- **Uso:** informe o caminho do SQLite cifrado e digite a senha utilizada na exportação. Os valores são mostrados no terminal.
- **Dependências específicas:** `pycryptodome`, `sqlite3`.

### 15. 26716-LPD-python-LOGs-http-ssh-e-ufw-stats-IPv4-IPv6-matplotlib.py
- **Objetivo:** mesma análise da opção 12, porém os gráficos são gerados pelo Matplotlib e incorporados como imagens base64 no HTML (`-matplotlib.html`).
- **Uso:** idêntico à opção 12; o relatório texto é compartilhado e o HTML fica em `reports/<log>_relatorio_http_ssh_ufw-stats-IPv4-IPv6-matplotlib.html`.
- **Dependências específicas:** `matplotlib` além do AWK auxiliar.

## Organização dos arquivos
- `reports/`, `baixados/`, `maxmind/`, `regular-expression-awk-ip-address-and-timestamp.awk`, os menus e os 15 scripts seguem ativos na raiz porque são imprescindíveis.
- Qualquer artefato que não é chamado pelos menus foi movido para `not-used/` para evitar confusão, mas continua versionado para consulta.

## Próximos passos
1. Configure o `.venv` e instale as dependências.
2. Gere as credenciais (se for usar o menu autenticado).
3. Execute o menu desejado, informe os caminhos dos logs e consulte os relatórios em `reports/` ou `baixados/`.

Bom trabalho e boas análises!
