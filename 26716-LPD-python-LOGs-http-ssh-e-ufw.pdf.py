#!/usr/bin/env python3
"""Extrai IPs/timestamps via AWK e mostra as origens dos acessos."""

import argparse
import os
import sys
import subprocess
from collections import Counter
from datetime import datetime, timezone

import geoip2.database
from geoip2.errors import AddressNotFoundError
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

# Bases ficam numa subpasta "maxmind" ao lado do script
def _caminho_relativo(*partes):
    return os.path.join(os.getcwd(), *partes)

BASE_MAXMIND = _caminho_relativo("maxmind")
CAMINHO_CITY = os.path.join(BASE_MAXMIND, "GeoLite2-City.mmdb")
CAMINHO_COUNTRY = os.path.join(BASE_MAXMIND, "GeoLite2-Country.mmdb")
AWK_SCRIPT = _caminho_relativo("regular-expression-awk-ip-address-and-timestamp.awk")
LOG_PADRAO = "/var/log/apache2/access.log"
LOGO_IPBEJA = _caminho_relativo("IPbeja_horizontal.png")
LOGO_ESTIG = _caminho_relativo("IPBeja_estig_horizontal.png")

FONTE_PADRAO = "Helvetica"
FONTE_PADRAO_NEGRITO = "Helvetica-Bold"


def _primeiro_caminho_existente(caminhos):
    for caminho in caminhos:
        if caminho and os.path.isfile(caminho):
            return caminho
    return None


def _texto_para_datetime(valor):
    try:
        if valor.endswith("Z"):
            valor = valor[:-1] + "+00:00"
        return datetime.fromisoformat(valor)
    except Exception:
        return None


def _intervalo_temporal(primeiro, ultimo):
    dt_primeiro = _texto_para_datetime(primeiro)
    dt_ultimo = _texto_para_datetime(ultimo)
    if not dt_primeiro or not dt_ultimo:
        return "Nao disponivel"
    intervalo = dt_ultimo - dt_primeiro
    total_segundos = int(intervalo.total_seconds())
    if total_segundos < 0:
        return "Nao disponivel"
    dias, resto = divmod(total_segundos, 86400)
    horas, resto = divmod(resto, 3600)
    minutos, segundos = divmod(resto, 60)
    partes = []
    if dias:
        partes.append(f"{dias}d")
    partes.append(f"{horas:02d}h{minutos:02d}m{segundos:02d}s")
    return " ".join(partes)


def configurar_fonte_consolas():
    global FONTE_PADRAO, FONTE_PADRAO_NEGRITO

    pasta_windows = os.environ.get("WINDIR", "C:\\Windows")
    candidatos_regular = [
        os.path.join(pasta_windows, "Fonts", "consola.ttf"),
        "/usr/share/fonts/truetype/msttcorefonts/Consola.ttf",
        "/usr/share/fonts/truetype/consolas/Consola.ttf",
    ]
    candidatos_bold = [
        os.path.join(pasta_windows, "Fonts", "consolab.ttf"),
        "/usr/share/fonts/truetype/msttcorefonts/Consolab.ttf",
        "/usr/share/fonts/truetype/consolas/Consolab.ttf",
    ]

    caminho_regular = _primeiro_caminho_existente(candidatos_regular)
    if not caminho_regular:
        return

    try:
        pdfmetrics.registerFont(TTFont("Consolas", caminho_regular))
        FONTE_PADRAO = "Consolas"
    except Exception:
        return

    caminho_bold = _primeiro_caminho_existente(candidatos_bold)
    if caminho_bold:
        try:
            pdfmetrics.registerFont(TTFont("Consolas-Bold", caminho_bold))
            FONTE_PADRAO_NEGRITO = "Consolas-Bold"
        except Exception:
            FONTE_PADRAO_NEGRITO = "Consolas"
    else:
        FONTE_PADRAO_NEGRITO = "Consolas"


configurar_fonte_consolas()


def _formatar_info_base(meta, nome_base):
    try:
        data_build = datetime.fromtimestamp(meta.build_epoch, timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S UTC"
        )
    except Exception:
        data_build = "desconhecida"
    return f"Base {nome_base}: tipo {meta.database_type} (build {data_build})"


def _obter_metadata(leitor):
    try:
        meta = leitor.metadata
        tentativas = 0
        while callable(meta) and tentativas < 3:
            meta = meta()
            tentativas += 1
        return meta if hasattr(meta, "build_epoch") else None
    except Exception:
        return None


def obter_argumentos():
    parser = argparse.ArgumentParser(
        description="Gera um relatorio PDF das origens de acessos HTTP/SSH/UFW"
    )
    parser.add_argument(
        "-l",
        "--log",
        "--logfile",
        dest="logfile",
        metavar="CAMINHO",
        help="Caminho completo do arquivo de log a analisar",
    )
    parser.add_argument(
        "logfile_pos",
        nargs="?",
        help="(Opcional) caminho do arquivo (compatibilidade)",
    )
    return parser.parse_args()


def para_iso8601(texto):
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


def obter_localizacao(ip, leitor_city, leitor_country):
    """Tenta devolver pais e cidade do IP."""
    pais = "Desconhecido"
    cidade = "Sem cidade"

    try:
        resposta_city = leitor_city.city(ip)
        if resposta_city.country.name:
            pais = resposta_city.country.name
        elif resposta_city.country.iso_code:
            pais = resposta_city.country.iso_code
        if resposta_city.city and resposta_city.city.name:
            cidade = resposta_city.city.name
        return pais, cidade
    except AddressNotFoundError:
        pass
    except Exception:
        pass

    try:
        resposta_country = leitor_country.country(ip)
        if resposta_country.country.name:
            pais = resposta_country.country.name
        elif resposta_country.country.iso_code:
            pais = resposta_country.country.iso_code
    except AddressNotFoundError:
        pass
    except Exception:
        pass

    return pais, cidade


def main():
    args = obter_argumentos()

    if args.logfile:
        caminho_log = args.logfile.strip()
    elif getattr(args, "logfile_pos", None):
        caminho_log = args.logfile_pos.strip()
    else:
        caminho_log = input(
            "Informe o caminho completo do arquivo de log (ex: /var/log/apache2/access.log): "
        ).strip()
        if not caminho_log:
            caminho_log = LOG_PADRAO

    if not caminho_log:
        print("Nenhum arquivo informado. Saindo.")
        sys.exit(1)

    if not os.path.isfile(caminho_log):
        print("Arquivo nao encontrado. Verifique o caminho.")
        sys.exit(1)

    info_bases = []

    try:
        leitor_city = geoip2.database.Reader(CAMINHO_CITY)
        leitor_country = geoip2.database.Reader(CAMINHO_COUNTRY)
    except FileNotFoundError:
        print("Base GeoLite2 nao encontrada na pasta maxmind.")
        sys.exit(1)
    except Exception as erro:
        print(f"Erro ao abrir base GeoLite2: {erro}")
        sys.exit(1)

    meta_city = _obter_metadata(leitor_city)
    if meta_city:
        info_bases.append(_formatar_info_base(meta_city, "GeoLite2 City"))
    meta_country = _obter_metadata(leitor_country)
    if meta_country:
        info_bases.append(_formatar_info_base(meta_country, "GeoLite2 Country"))

    registros = []

    with leitor_city, leitor_country:
        try:
            entradas = executar_awk(caminho_log)
        except Exception as erro:
            print(erro)
            sys.exit(1)

        for ip, timestamp_bruto in entradas:
            if not ip or not timestamp_bruto:
                continue
            timestamp = para_iso8601(timestamp_bruto)
            pais, cidade = obter_localizacao(ip, leitor_city, leitor_country)
            registros.append(
                {
                    "timestamp": timestamp,
                    "ip": ip,
                    "country": pais,
                    "city": cidade,
                }
            )

    if not registros:
        print("Nenhum acesso identificado no log; PDF nao foi criado.")
        return

    contagem_pais = Counter(item["country"] for item in registros)
    contagem_cidade = Counter((item["country"], item["city"]) for item in registros)
    contagem_ip = Counter(item["ip"] for item in registros)

    registros.sort(key=lambda item: (item["country"], item["city"], item["ip"], item["timestamp"]))

    timestamp_execucao = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    nome_log = os.path.basename(caminho_log)
    diretorio_relativo = os.path.relpath(os.path.dirname(caminho_log), os.getcwd())
    if diretorio_relativo in (".", ""):
        componente = "raiz"
    else:
        componente = diretorio_relativo.replace(os.sep, "_")
    nome_saida = f"26716-{timestamp_execucao}-{componente}-{nome_log}.pdf"
    caminho_saida = os.path.join(os.getcwd(), nome_saida)

    timestamps_ordenados = sorted(item["timestamp"] for item in registros)
    primeiro_timestamp = timestamps_ordenados[0]
    ultimo_timestamp = timestamps_ordenados[-1]
    intervalo_temporal = _intervalo_temporal(primeiro_timestamp, ultimo_timestamp)

    gerar_pdf(
        caminho_saida,
        nome_saida,
        caminho_log,
        registros,
        contagem_pais,
        contagem_cidade,
        contagem_ip,
        primeiro_timestamp,
        ultimo_timestamp,
        intervalo_temporal,
        info_bases,
    )
    print(f"PDF criado em {nome_saida}")


def gerar_pdf(
    caminho_saida,
    nome_saida,
    caminho_log,
    registros,
    contagem_pais,
    contagem_cidade,
    contagem_ip,
    primeiro_timestamp,
    ultimo_timestamp,
    intervalo_temporal,
    info_bases,
):
    estilos = getSampleStyleSheet()
    estilos["BodyText"].fontName = FONTE_PADRAO
    estilos["Normal"].fontName = FONTE_PADRAO
    estilos["Heading1"].fontName = FONTE_PADRAO_NEGRITO
    estilos["Heading2"].fontName = FONTE_PADRAO_NEGRITO
    estilos["Title"].fontName = FONTE_PADRAO_NEGRITO
    estilos["Code"].fontName = FONTE_PADRAO
    estilo_ip = estilos["Code"].clone("IPStyle")
    estilo_ip.fontName = FONTE_PADRAO
    estilo_ip.fontSize = 8
    estilo_ip.leading = 9
    estilo_ip.wordWrap = "CJK"

    doc = SimpleDocTemplate(
        caminho_saida,
        pagesize=A4,
        leftMargin=42,
        rightMargin=42,
        topMargin=96,
        bottomMargin=36,
    )

    elementos = []
    elementos.append(Paragraph("26716", estilos["Heading1"]))
    elementos.append(Paragraph("Relatorio de acessos", estilos["Title"]))
    elementos.append(Paragraph(f"Arquivo analisado: {caminho_log}", estilos["Normal"]))
    elementos.append(Paragraph(f"Arquivo gerado: {nome_saida}", estilos["Normal"]))
    elementos.append(Paragraph(f"Total de entradas: {len(registros)}", estilos["Normal"]))
    elementos.append(Paragraph(f"Primeiro timestamp: {primeiro_timestamp}", estilos["Normal"]))
    elementos.append(Paragraph(f"Ultimo timestamp: {ultimo_timestamp}", estilos["Normal"]))
    elementos.append(Paragraph(f"Intervalo temporal: {intervalo_temporal}", estilos["Normal"]))
    for info in info_bases:
        elementos.append(Paragraph(info, estilos["Normal"]))
    elementos.append(Spacer(1, 12))

    largura_total = A4[0] - (doc.leftMargin + doc.rightMargin)

    def _tabela_contagem(titulo_secao, cabecalho, linhas, col_widths):
        if not linhas:
            return
        elementos.append(Spacer(1, 18))
        elementos.append(Paragraph(titulo_secao, estilos["Heading2"]))
        tabela_local = Table([cabecalho] + linhas, repeatRows=1, colWidths=col_widths)
        tabela_local.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#3f6ea3")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("FONTNAME", (0, 0), (-1, 0), FONTE_PADRAO_NEGRITO),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [colors.white, colors.HexColor("#f0f4f8")],
                    ),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ]
            )
        )
        elementos.append(tabela_local)

    linhas_pais = [
        [Paragraph(pais, estilos["BodyText"]), count]
        for pais, count in sorted(
            contagem_pais.items(), key=lambda item: (-item[1], item[0])
        )
    ]
    _tabela_contagem(
        "Totais por pais",
        ["Pais", "Total"],
        linhas_pais,
        [largura_total * 0.7, largura_total * 0.3],
    )

    linhas_cidade = [
        [
            Paragraph(pais, estilos["BodyText"]),
            Paragraph(cidade, estilos["BodyText"]),
            count,
        ]
        for (pais, cidade), count in sorted(
            contagem_cidade.items(), key=lambda item: (-item[1], item[0][0], item[0][1])
        )
    ]
    _tabela_contagem(
        "Totais por cidade",
        ["Pais", "Cidade", "Total"],
        linhas_cidade,
        [largura_total * 0.4, largura_total * 0.4, largura_total * 0.2],
    )

    linhas_ip = [
        [Paragraph(ip, estilo_ip), count]
        for ip, count in sorted(
            contagem_ip.items(), key=lambda item: (-item[1], item[0])
        )
    ]
    _tabela_contagem(
        "Totais por IP",
        ["IP", "Total"],
        linhas_ip,
        [largura_total * 0.7, largura_total * 0.3],
    )

    elementos.append(Spacer(1, 18))
    elementos.append(Paragraph("Detalhamento por acesso", estilos["Heading2"]))

    dados_tabela = [["Timestamp", "IP", "Pais", "Cidade"]]
    for item in registros:
        dados_tabela.append(
            [
                Paragraph(item["timestamp"], estilos["BodyText"]),
                Paragraph(item["ip"], estilo_ip),
                Paragraph(item["country"], estilos["BodyText"]),
                Paragraph(item["city"], estilos["BodyText"]),
            ]
        )

    tabela = Table(
        dados_tabela,
        repeatRows=1,
        colWidths=[
            largura_total * 0.30,
            largura_total * 0.28,
            largura_total * 0.22,
            largura_total * 0.20,
        ],
    )
    tabela.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2b547e")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("FONTNAME", (0, 0), (-1, 0), FONTE_PADRAO_NEGRITO),
                ("FONTSIZE", (0, 0), (-1, 0), 10),
                ("FONTSIZE", (0, 1), (-1, -1), 8),
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [colors.white, colors.HexColor("#f5f5f5")],
                ),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]
        )
    )
    elementos.append(tabela)

    titulo = "Relatorio de IPs"

    def cabecalho(canvas, doc):
        desenhar_cabecalho(canvas, doc, titulo, LOGO_IPBEJA, LOGO_ESTIG)

    doc.build(elementos, onFirstPage=cabecalho, onLaterPages=cabecalho)


def desenhar_cabecalho(canvas, doc, titulo, logo_esquerda, logo_direita):
    canvas.saveState()
    largura, altura = A4
    altura_logo = 3 * cm
    margem_superior = 32
    y_topo = altura - altura_logo - margem_superior

    def desenhar_logo(caminho, x, alinhamento_direita=False):
        if not os.path.isfile(caminho):
            return 0
        try:
            imagem = ImageReader(caminho)
            largura_original, altura_original = imagem.getSize()
            proporcao = largura_original / altura_original if altura_original else 1
            largura_logo = altura_logo * proporcao
            destino_x = x - largura_logo if alinhamento_direita else x
            canvas.drawImage(
                caminho,
                destino_x,
                y_topo,
                width=largura_logo,
                height=altura_logo,
                preserveAspectRatio=True,
                mask="auto",
            )
            return largura_logo
        except Exception:
            return 0

    largura_logo_esquerda = desenhar_logo(logo_esquerda, doc.leftMargin)
    largura_logo_direita = desenhar_logo(
        logo_direita,
        largura - doc.rightMargin,
        alinhamento_direita=True,
    )

    texto_area_inicio = doc.leftMargin + largura_logo_esquerda + 10
    texto_area_fim = largura - doc.rightMargin - largura_logo_direita - 10
    if texto_area_fim <= texto_area_inicio:
        texto_area_inicio = doc.leftMargin
        texto_area_fim = largura - doc.rightMargin
    texto_centro = texto_area_inicio + (texto_area_fim - texto_area_inicio) / 2

    canvas.setFont(FONTE_PADRAO_NEGRITO, 13)
    canvas.drawCentredString(texto_centro, y_topo + altura_logo + 6, titulo)
    canvas.setFont(FONTE_PADRAO, 9)
    canvas.drawCentredString(
        texto_centro,
        y_topo + altura_logo - 8,
        f"Gerado em {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
    )
    canvas.drawRightString(
        largura - doc.rightMargin,
        y_topo - 4,
        os.path.basename(doc.filename),
    )
    canvas.line(doc.leftMargin, y_topo - 24, largura - doc.rightMargin, y_topo - 24)
    canvas.restoreState()


if __name__ == "__main__":
    main()
