#!/usr/bin/env python3
"""Extrai IPs/timestamps via AWK e mostra as origens dos acessos."""

import os
import sys
import subprocess
from datetime import datetime

import geoip2.database
from geoip2.errors import AddressNotFoundError

# Bases ficam numa subpasta "maxmind" ao lado do script
def _caminho_relativo(*partes):
    return os.path.join(os.getcwd(), *partes)

BASE_MAXMIND = _caminho_relativo("maxmind")
CAMINHO_CITY = os.path.join(BASE_MAXMIND, "GeoLite2-City.mmdb")
CAMINHO_COUNTRY = os.path.join(BASE_MAXMIND, "GeoLite2-Country.mmdb")
AWK_SCRIPT = _caminho_relativo("regular-expression-awk-ip-address-and-timestamp.awk")
LOG_PADRAO = "/var/log/apache2/access.log"


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
        raise FileNotFoundError("Script AWK nao encontrado na raiz do projecto.")

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


def contar_linhas(caminho_log):
    try:
        with open(caminho_log, "r", encoding="utf-8", errors="ignore") as ficheiro:
            return sum(1 for _ in ficheiro)
    except Exception as erro:
        raise RuntimeError(f"Nao foi possivel contar as linhas do log: {erro}") from erro


def main():
    print("Analisador de logs (IP e timestamp via AWK)")

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
        total_linhas = contar_linhas(caminho_log)
    except Exception as erro:
        print(erro)
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
    linhas_validas = 0

    with leitor_city, leitor_country:
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
            pais, cidade = obter_localizacao(ip, leitor_city, leitor_country)

            if pais not in registos_por_pais:
                registos_por_pais[pais] = []
            registos_por_pais[pais].append({"ip": ip, "timestamp": timestamp, "cidade": cidade})

    print("\nResumo do processamento:")
    print(f"Linhas no ficheiro: {total_linhas}")
    print(f"Registos extraidos via AWK: {linhas_validas}")
    if linhas_validas <= total_linhas:
        print(f"Linhas sem correspondencia: {total_linhas - linhas_validas}")
    else:
        print("Nota: UFW pode gerar mais de um registo por linha (SRC/DST).")

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
