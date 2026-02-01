#!/usr/bin/env python3
"""Le um log HTTP simples e mostra origem dos acessos."""

import os
import re
import sys

import geoip2.database
from geoip2.errors import AddressNotFoundError
from datetime import datetime

# Bases ficam numa subpasta "maxmind" ao lado do script
BASE_MAXMIND = os.path.join(os.getcwd(), "maxmind")
CAMINHO_CITY = os.path.join(BASE_MAXMIND, "GeoLite2-City.mmdb")
CAMINHO_COUNTRY = os.path.join(BASE_MAXMIND, "GeoLite2-Country.mmdb")
LOG_PADRAO = "/var/log/apache2/access.log"

# Regras simples para extrair timestamp e IPs
PADRAO_HTTP_TIMESTAMP = re.compile(r"\[(?P<http>\d{1,2}/[A-Za-z]{3}/\d{4}:[^\]]+)\]")
PADRAO_SYSLOG_TIMESTAMP = re.compile(r"^(?P<syslog>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
PADRAO_TIMESTAMP = re.compile(r"\[(?P<timestamp>[^\]]+)\]")
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
            r = valor.strftime("%Y-%m-%dT%H:%M:%S")
            return r
        except Exception:
            return texto

    return texto
PADROES_DIRETOS = [
    re.compile(r"^\[([0-9A-Fa-f:.]+)\]:[0-9]+"),
    re.compile(r"\[client ([0-9A-Fa-f:.]+)\]"),
    re.compile(r"from ([0-9A-Fa-f:.]+) port [0-9]+"),
    re.compile(r"rhost=([0-9A-Fa-f:.]+)"),
    re.compile(r"Received disconnect from ([0-9A-Fa-f:.]+):"),
    re.compile(r"Connection closed by ([0-9A-Fa-f:.]+)"),
    re.compile(r"SRC=([0-9A-Fa-f:.]+)"),
]
CARACTERES_REMOVER = re.compile(r"[\[\]\"'(),;]")
PORTO_FINAL_IPV4 = re.compile(r":[0-9]+$")
PORTO_FINAL_IPV6 = re.compile(r"\]:[0-9]+$")
PREFIXOS_REMOVER = ("SRC=", "DST=", "MAC=", "client")


def limpar_token(token):
    limpo = CARACTERES_REMOVER.sub("", token)
    for prefixo in PREFIXOS_REMOVER:
        limpo = limpo.replace(prefixo, "")
    if limpo.startswith("[") and "]" in limpo:
        limpo = limpo.lstrip("[")
    limpo = PORTO_FINAL_IPV6.sub("", limpo)
    return PORTO_FINAL_IPV4.sub("", limpo)


def eh_ipv4(valor):
    partes = valor.split(".")
    if len(partes) != 4:
        return False
    for parte in partes:
        if not parte.isdigit():
            return False
        if not 0 <= int(parte) <= 255:
            return False
    return True


def eh_ipv6(valor):
    if valor == "::1":
        return True
    partes = valor.split(":")
    if not 2 <= len(partes) <= 9:
        return False
    for parte in partes:
        if not parte:
            continue
        if not re.fullmatch(r"[0-9a-fA-F]+", parte):
            return False
    return len(valor) > 8


def extrair_ip(texto):
    for padrao in PADROES_DIRETOS:
        resultado = padrao.search(texto)
        if resultado:
            ip = resultado.group(1)
            ip = limpar_token(ip)
            if eh_ipv4(ip) or eh_ipv6(ip):
                return ip

    for token in texto.split():
        limpo = limpar_token(token)
        if not limpo:
            continue
        if eh_ipv4(limpo) or eh_ipv6(limpo):
            return limpo

    return None


def obter_timestamp(linha):
    http = PADRAO_HTTP_TIMESTAMP.search(linha)
    if http:
        return http.group("http")

    syslog = PADRAO_SYSLOG_TIMESTAMP.search(linha)
    if syslog:
        return syslog.group("syslog")

    generico = PADRAO_TIMESTAMP.search(linha)
    if generico:
        conteudo = generico.group("timestamp")
        if not conteudo.isdigit():
            return conteudo

    return "Sem timestamp"


def ler_linha(linha):
    ip = extrair_ip(linha)
    if not ip:
        return None

    timestamp = obter_timestamp(linha)
    formato_iso = para_iso8601(timestamp)

    return ip, formato_iso


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
    print("Analisador simples de logs HTTP")

    if len(sys.argv) > 1:
        caminho_log = sys.argv[1].strip()
        if not caminho_log:
            print("Parametro do log vazio. Forneca um caminho valido.")
            sys.exit(1)
    else:
        caminho_log = input(
            "Informe o caminho completo do ficheiro de log (ex: /var/log/apache2/access.log): "
        ).strip()
        if not caminho_log:
            caminho_log = LOG_PADRAO

    if not caminho_log:
        print("Nenhum ficheiro informado. Saindo.")
        sys.exit(1)

    if not os.path.isfile(caminho_log):
        print("Ficheiro nao encontrado. Verifique o caminho.")
        sys.exit(1)

    try:
        leitor_city = geoip2.database.Reader(CAMINHO_CITY)
        leitor_country = geoip2.database.Reader(CAMINHO_COUNTRY)
    except FileNotFoundError:
        print("Base GeoLite2 nao encontrada na pasta maxmind.")
        sys.exit(1)
    except Exception as erro:
        print(f"Erro ao abrir base GeoLite2: {erro}")
        sys.exit(1)

    registos_por_pais = {}
    total_linhas = 0
    linhas_validas = 0
    linhas_ignoradas = 0

    with leitor_city, leitor_country, open(caminho_log, "r", encoding="utf-8", errors="ignore") as ficheiro:
        for linha in ficheiro:
            total_linhas += 1
            dados = ler_linha(linha)
            if not dados:
                linhas_ignoradas += 1
                continue

            ip, timestamp = dados
            pais, cidade = obter_localizacao(ip, leitor_city, leitor_country)

            if pais not in registos_por_pais:
                registos_por_pais[pais] = []
            registos_por_pais[pais].append({"ip": ip, "timestamp": timestamp, "cidade": cidade})
            linhas_validas += 1

    print("\nResumo do processamento:")
    print(f"Linhas totais: {total_linhas}")
    print(f"Linhas validas: {linhas_validas}")
    print(f"Linhas ignoradas: {linhas_ignoradas}")

    if not registos_por_pais:
        print("Nenhum acesso identificado no log.")
        return

    print("\nOrigens por pais:")
    for pais in sorted(registos_por_pais, key=lambda chave: len(registos_por_pais[chave]), reverse=True):
        acessos = registos_por_pais[pais]
        print(f"\nPais: {pais} | Total: {len(acessos)}")
        for acesso in acessos:
            timestamp = acesso["timestamp"]
            ip = acesso["ip"]
            cidade = acesso["cidade"]
            print(f" - {timestamp} | {ip} | {cidade}")


if __name__ == "__main__":
    main()
