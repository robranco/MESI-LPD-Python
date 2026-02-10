#!/usr/bin/env python3
"""Extrai IPs/timestamps via AWK e resume acessos IPv4/IPv6."""

import base64
import os
import sys
import subprocess
from datetime import datetime
from io import BytesIO
import ipaddress

import matplotlib.pyplot as plt


class Tee:
    def __init__(self, *destinos):
        self.destinos = destinos

    def write(self, dados):
        for destino in self.destinos:
            destino.write(dados)

    def flush(self):
        for destino in self.destinos:
            destino.flush()

def _caminho_relativo(*partes):
    return os.path.join(os.getcwd(), *partes)

AWK_SCRIPT = _caminho_relativo("regular-expression-awk-ip-address-and-timestamp.awk")
LOG_PADRAO = "/var/log/apache2/access.log"
PASTA_RELATORIOS = _caminho_relativo("reports")
FORMATOS_TIMESTAMP_CONHECIDOS = [
    "%d/%b/%Y:%H:%M:%S %z",
    "%a %b %d %H:%M:%S.%f %Y",
    "%a %b %d %H:%M:%S %Y",
]


def obter_caminho_log(argv=None):
    argumentos = argv if argv is not None else sys.argv[1:]
    if argumentos:
        caminho = argumentos[0].strip()
        if not caminho:
            raise ValueError("Parametro de log vazio. Forneca um caminho valido.")
        return caminho

    caminho = input(
        "Informe o caminho completo do arquivo de log (ex: /var/log/apache2/access.log): "
    ).strip()
    return caminho or LOG_PADRAO


def _pie_chart_base64(valores, labels, cores, titulo):
    fig, eixo = plt.subplots(figsize=(4, 4))
    total = sum(valores)
    if total == 0:
        valores_plot = [1]
        labels_plot = ["Sem dados"]
        cores_plot = ["#cccccc"]
        autopct_fn = lambda pct: ""
    else:
        valores_plot = valores
        labels_plot = labels
        cores_plot = cores
        autopct_fn = lambda pct: f"{pct:.1f}%"

    eixo.pie(
        valores_plot,
        labels=labels_plot,
        colors=cores_plot,
        autopct=autopct_fn,
        startangle=90,
    )
    eixo.set_title(titulo)
    eixo.axis("equal")

    buffer = BytesIO()
    fig.savefig(buffer, format="png", bbox_inches="tight", transparent=True)
    plt.close(fig)
    return base64.b64encode(buffer.getvalue()).decode("ascii")


def para_iso8601(texto):
    texto = texto.strip()

    for formato in FORMATOS_TIMESTAMP_CONHECIDOS:
        try:
            valor = datetime.strptime(texto, formato)
            return valor.isoformat()
        except ValueError:
            continue

    meses = {
        "Jan": 1,
        "Feb": 2,
        "Mar": 3,
        "Apr": 4,
        "May": 5,
        "Jun": 6,
        "Jul": 7,
        "Aug": 8,
        "Sep": 9,
        "Oct": 10,
        "Nov": 11,
        "Dec": 12,
    }

    if "/" in texto and ":" in texto:
        try:
            parte_data, resto = texto.split(":", 1)
            dia, mes_abrev, ano = parte_data.split("/")
            hora = resto[:8]
            fuso = resto[9:].strip() if len(resto) > 9 else "+0000"
            mes = meses.get(mes_abrev, 1)
            valor = datetime(
                int(ano), mes, int(dia), int(hora[0:2]), int(hora[3:5]), int(hora[6:8])
            )
            fuso_formatado = fuso[:3] + ":" + fuso[3:] if len(fuso) == 5 else ""
            return valor.strftime("%Y-%m-%dT%H:%M:%S") + fuso_formatado
        except Exception:
            return texto

    partes = texto.split()
    if len(partes) == 3:
        mes_abrev, dia, hora = partes
        ano_atual = datetime.now().year
        mes = meses.get(mes_abrev, 1)
        try:
            valor = datetime(
                ano_atual,
                mes,
                int(dia),
                int(hora[0:2]),
                int(hora[3:5]),
                int(hora[6:8]),
            )
            return valor.strftime("%Y-%m-%dT%H:%M:%S")
        except Exception:
            return texto

    return texto


def _converter_para_datetime(timestamp_iso):
    texto = timestamp_iso.strip()
    try:
        return datetime.fromisoformat(texto.replace("Z", "+00:00"))
    except ValueError:
        pass

    for formato in FORMATOS_TIMESTAMP_CONHECIDOS:
        try:
            return datetime.strptime(texto, formato)
        except ValueError:
            continue

    return None


def gerar_relatorio_html(caminho_html, contexto):
    imagem_total = _pie_chart_base64(
        valores=[contexto["ipv4_total"], contexto["ipv6_total"]],
        labels=["IPv4", "IPv6"],
        cores=["#1f77b4", "#ff7f0e"],
        titulo="Distribuicao total",
    )

    imagem_unicos = _pie_chart_base64(
        valores=[contexto["ipv4_unicos"], contexto["ipv6_unicos"]],
        labels=["IPv4", "IPv6"],
        cores=["#2ca02c", "#d62728"],
        titulo="IPs unicos",
    )

    ipv4_repetidos = max(contexto["ipv4_total"] - contexto["ipv4_unicos"], 0)
    ipv6_repetidos = max(contexto["ipv6_total"] - contexto["ipv6_unicos"], 0)

    imagem_ipv4_unicos_vs_total = _pie_chart_base64(
        valores=[contexto["ipv4_unicos"], ipv4_repetidos],
        labels=["IPv4 unicos", "IPv4 repetidos"],
        cores=["#17becf", "#9467bd"],
        titulo="IPv4 unicos x total",
    )

    imagem_ipv6_unicos_vs_total = _pie_chart_base64(
        valores=[contexto["ipv6_unicos"], ipv6_repetidos],
        labels=["IPv6 unicos", "IPv6 repetidos"],
        cores=["#8c564b", "#e377c2"],
        titulo="IPv6 unicos x total",
    )

    html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="utf-8" />
    <title>Resumo IPv4/IPv6</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 2rem; background: #f4f4f4; color: #222; }}
        h1 {{ margin-bottom: 0.5rem; }}
        section {{ background: #fff; padding: 1.5rem; border-radius: 12px; box-shadow: 0 2px 6px rgba(0,0,0,0.1); margin-bottom: 1.5rem; }}
        .graficos {{ display: flex; flex-wrap: wrap; gap: 2rem; }}
        .grafico {{ flex: 1 1 280px; text-align: center; }}
        .grafico img {{ width: 320px; height: 320px; max-width: 100%; }}
        ul {{ list-style: none; padding: 0; }}
        li {{ margin: 0.25rem 0; }}
    </style>
</head>
<body>
    <h1>Resumo de acessos por protocolo IP</h1>
    <section>
        <h2>Estatisticas gerais</h2>
        <ul>
            <li>Linhas no arquivo: {contexto["total_linhas"]}</li>
            <li>Registros extraidos via AWK: {contexto["linhas_validas"]}</li>
            <li>Linhas sem correspondencia: {contexto.get("linhas_sem_correspondencia", 'N/D')}</li>
            <li>Primeiro evento: {contexto["primeiro_evento"] or 'N/D'}</li>
            <li>Ultimo evento: {contexto["ultimo_evento"] or 'N/D'}</li>
        </ul>
    </section>

    <section class="graficos">
        <div class="grafico">
            <h2>Distribuicao total</h2>
            <img src="data:image/png;base64,{imagem_total}" alt="Distribuicao total" />
            <p>IPv4: {contexto['ipv4_total']} | IPv6: {contexto['ipv6_total']}</p>
        </div>
        <div class="grafico">
            <h2>Distribuicao de IPs unicos</h2>
            <img src="data:image/png;base64,{imagem_unicos}" alt="Distribuicao de IPs unicos" />
            <p>IPv4: {contexto['ipv4_unicos']} | IPv6: {contexto['ipv6_unicos']}</p>
        </div>
        <div class="grafico">
            <h2>IPv4 unicos x total</h2>
            <img src="data:image/png;base64,{imagem_ipv4_unicos_vs_total}" alt="Proporcao IPv4 unicos" />
            <p>Unicos: {contexto['ipv4_unicos']} | Repetidos: {ipv4_repetidos}</p>
        </div>
        <div class="grafico">
            <h2>IPv6 unicos x total</h2>
            <img src="data:image/png;base64,{imagem_ipv6_unicos_vs_total}" alt="Proporcao IPv6 unicos" />
            <p>Unicos: {contexto['ipv6_unicos']} | Repetidos: {ipv6_repetidos}</p>
        </div>
    </section>

    <section>
        <h2>Percentuais</h2>
        <ul>
            <li>Entradas IPv4: {contexto['perc_ipv4']:.2f}% | Entradas IPv6: {contexto['perc_ipv6']:.2f}%</li>
            <li>IPs unicos IPv4: {contexto['perc_ipv4_unico']:.2f}% | IPs unicos IPv6: {contexto['perc_ipv6_unico']:.2f}%</li>
        </ul>
    </section>

</body>
</html>
"""

    with open(caminho_html, "w", encoding="utf-8") as ficheiro:
        ficheiro.write(html)


def executar_awk(caminho_log):
    """Chama o AWK para obter timestamp e IP de cada linha."""
    if not os.path.isfile(AWK_SCRIPT):
        raise FileNotFoundError("Script AWK nao encontrado na raiz do projeto.")

    comando = ["awk", "-f", AWK_SCRIPT, caminho_log]
    try:
        resultado = subprocess.run(
            comando,
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError as erro:
        raise FileNotFoundError("awk nao foi encontrado no PATH.") from erro
    except subprocess.CalledProcessError as erro:
        mensagem = erro.stderr.strip() or erro.stdout.strip() or str(erro)
        raise RuntimeError(f"Falha ao executar awk: {mensagem}") from erro

    for linha in resultado.stdout.splitlines():
        linha = linha.strip()
        if not linha:
            continue
        partes = linha.split("\t", 1)
        if len(partes) != 2:
            continue
        timestamp_bruto, ip = partes
        yield ip.strip(), timestamp_bruto.strip("[] ")


def contar_linhas(caminho_log):
    try:
        with open(caminho_log, "r", encoding="utf-8", errors="ignore") as arquivo:
            return sum(1 for _ in arquivo)
    except Exception as erro:
        raise RuntimeError(f"Nao foi possivel contar as linhas do log: {erro}") from erro


def main(argv=None):
    print("Analisador de logs (IP e timestamp via AWK)")

    try:
        caminho_log = obter_caminho_log(argv)
    except ValueError as erro:
        print(erro)
        sys.exit(1)

    if not caminho_log:
        print("Nenhum arquivo informado. Saindo.")
        sys.exit(1)

    if not os.path.isfile(caminho_log):
        print("Arquivo nao encontrado. Verifique o caminho.")
        sys.exit(1)

    os.makedirs(PASTA_RELATORIOS, exist_ok=True)
    nome_base = os.path.basename(caminho_log) or "log"
    caminho_relatorio = os.path.join(PASTA_RELATORIOS, f"{nome_base}_relatorio_http_ssh_ufw-stats-IPv4-IPv6.txt")
    caminho_relatorio_html = os.path.join(
        PASTA_RELATORIOS,
        f"{nome_base}_relatorio_http_ssh_ufw-stats-IPv4-IPv6-matplotlib.html",
    )

    stdout_original = sys.stdout
    relatorio = open(caminho_relatorio, "w", encoding="utf-8")
    sys.stdout = Tee(sys.stdout, relatorio)

    try:
        try:
            total_linhas = contar_linhas(caminho_log)
        except Exception as erro:
            print(erro)
            sys.exit(1)

        linhas_validas = 0
        ipv4_total = 0
        ipv6_total = 0
        ipv4_unicos = set()
        ipv6_unicos = set()
        primeiro_evento = None
        ultimo_evento = None
        primeiro_evento_dt = None
        ultimo_evento_dt = None

        try:
            entradas = executar_awk(caminho_log)
        except Exception as erro:
            print(erro)
            sys.exit(1)

        for ip, timestamp_bruto in entradas:
            if not ip or not timestamp_bruto:
                continue
            linhas_validas += 1
            timestamp = para_iso8601(timestamp_bruto)
            timestamp_dt = _converter_para_datetime(timestamp)

            if timestamp_dt is not None:
                if primeiro_evento_dt is None or timestamp_dt < primeiro_evento_dt:
                    primeiro_evento_dt = timestamp_dt
                    primeiro_evento = timestamp
                if ultimo_evento_dt is None or timestamp_dt > ultimo_evento_dt:
                    ultimo_evento_dt = timestamp_dt
                    ultimo_evento = timestamp
            else:
                if primeiro_evento is None:
                    primeiro_evento = timestamp
                ultimo_evento = timestamp

            try:
                ip_objeto = ipaddress.ip_address(ip)
            except ValueError:
                continue

            if ip_objeto.version == 4:
                ipv4_total += 1
                ipv4_unicos.add(ip_objeto.compressed)
            elif ip_objeto.version == 6:
                ipv6_total += 1
                ipv6_unicos.add(ip_objeto.compressed)

        linhas_sem_correspondencia = total_linhas - linhas_validas if linhas_validas <= total_linhas else None

        print("\nResumo do processamento:")
        print(f"Linhas no arquivo: {total_linhas}")
        print(f"Registros extraidos via AWK: {linhas_validas}")
        if linhas_sem_correspondencia is not None:
            print(f"Linhas sem correspondencia: {linhas_sem_correspondencia}")
        else:
            print("Nota: UFW pode gerar mais de um registro por linha (SRC/DST).")

        total_registos_ip = ipv4_total + ipv6_total
        total_ips_unicos = len(ipv4_unicos) + len(ipv6_unicos)

        if total_registos_ip > 0:
            perc_ipv4 = (ipv4_total / total_registos_ip) * 100
            perc_ipv6 = (ipv6_total / total_registos_ip) * 100
        else:
            perc_ipv4 = perc_ipv6 = 0.0

        if total_ips_unicos > 0:
            perc_ipv4_unico = (len(ipv4_unicos) / total_ips_unicos) * 100
            perc_ipv6_unico = (len(ipv6_unicos) / total_ips_unicos) * 100
        else:
            perc_ipv4_unico = perc_ipv6_unico = 0.0

        print("\nResumo por protocolo IP:")
        print(f"Total de entradas IPv4: {ipv4_total}")
        print(f"IPv4 unicos: {len(ipv4_unicos)}")
        print(f"Total de entradas IPv6: {ipv6_total}")
        print(f"IPv6 unicos: {len(ipv6_unicos)}")
        print(f"Distribuicao de entradas: IPv4 {perc_ipv4:.2f}% | IPv6 {perc_ipv6:.2f}%")
        print(f"Distribuicao de IPs unicos: IPv4 {perc_ipv4_unico:.2f}% | IPv6 {perc_ipv6_unico:.2f}%")

        print("\nIntervalo temporal:")
        print(f"Primeiro evento: {primeiro_evento or 'N/D'}")
        print(f"Ultimo evento: {ultimo_evento or 'N/D'}")

        contexto_html = {
            "total_linhas": total_linhas,
            "linhas_validas": linhas_validas,
            "linhas_sem_correspondencia": linhas_sem_correspondencia if linhas_sem_correspondencia is not None else "N/D",
            "primeiro_evento": primeiro_evento,
            "ultimo_evento": ultimo_evento,
            "ipv4_total": ipv4_total,
            "ipv6_total": ipv6_total,
            "ipv4_unicos": len(ipv4_unicos),
            "ipv6_unicos": len(ipv6_unicos),
            "perc_ipv4": perc_ipv4,
            "perc_ipv6": perc_ipv6,
            "perc_ipv4_unico": perc_ipv4_unico,
            "perc_ipv6_unico": perc_ipv6_unico,
        }
        gerar_relatorio_html(caminho_relatorio_html, contexto_html)

        print(f"\nRelatorio salvo em: {caminho_relatorio}")
        print(f"Relatorio HTML salvo em: {caminho_relatorio_html}")
    finally:
        sys.stdout = stdout_original
        relatorio.close()


if __name__ == "__main__":
    main(sys.argv[1:])
