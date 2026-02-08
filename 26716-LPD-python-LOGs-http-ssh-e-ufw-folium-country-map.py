#!/usr/bin/env python3
"""Script simples: lê logs, salva CSV e cria mapa por país."""

import csv
import os
import sys
import subprocess
from datetime import datetime

import folium
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
PASTA_RELATORIOS = _caminho_relativo("reports")


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
    """Chama AWK para puxar timestamp e IP de cada linha."""
    if not os.path.isfile(AWK_SCRIPT):
        raise FileNotFoundError("Script AWK nao encontrado.")

    comando = ["awk", "-f", AWK_SCRIPT, caminho_log]
    try:
        resultado = subprocess.run(comando, capture_output=True, text=True, check=True)
    except FileNotFoundError as erro:
        raise FileNotFoundError("awk nao está no PATH.") from erro
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
    """Retorna pais e coordenadas aproximadas do IP."""
    pais = "Desconhecido"
    lat_ip = None
    lon_ip = None

    try:
        resposta_city = leitor_city.city(ip)
        if resposta_city.country.name:
            pais = resposta_city.country.name
        elif resposta_city.country.iso_code:
            pais = resposta_city.country.iso_code
        if resposta_city.location:
            lat_ip = resposta_city.location.latitude
            lon_ip = resposta_city.location.longitude
        return pais, lat_ip, lon_ip
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
        if resposta_country.location:
            lat_ip = resposta_country.location.latitude
            lon_ip = resposta_country.location.longitude
    except AddressNotFoundError:
        pass
    except Exception:
        pass

    return pais, lat_ip, lon_ip


def contar_linhas(caminho_log):
    try:
        with open(caminho_log, "r", encoding="utf-8", errors="ignore") as ficheiro:
            return sum(1 for _ in ficheiro)
    except Exception as erro:
        raise RuntimeError(f"Nao foi possivel contar as linhas do log: {erro}") from erro


def garantir_pasta_relatorios():
    os.makedirs(PASTA_RELATORIOS, exist_ok=True)


def main():
    print("=== Analise simples de logs HTTP/SSH/UFW ===")

    if len(sys.argv) > 1:
        caminho_log = sys.argv[1].strip()
    else:
        caminho_log = input(
            "Informe o caminho completo do log (ex: /var/log/apache2/access.log): "
        ).strip()

    if not caminho_log:
        caminho_log = LOG_PADRAO

    if not os.path.isfile(caminho_log):
        print("Nao encontrei o ficheiro informado.")
        sys.exit(1)

    garantir_pasta_relatorios()

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
    dados_csv = []
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
            pais, lat_ip, lon_ip = obter_localizacao(ip, leitor_city, leitor_country)

            if pais not in registos_por_pais:
                registos_por_pais[pais] = {
                    "total": 0,
                    "coordenadas_ip": [],
                }
            info_pais = registos_por_pais[pais]
            info_pais["total"] += 1
            if lat_ip is not None and lon_ip is not None:
                info_pais["coordenadas_ip"].append((lat_ip, lon_ip))

            dados_csv.append({
                "timestamp": timestamp,
                "ip": ip,
                "pais": pais,
                "latitude": lat_ip,
                "longitude": lon_ip,
            })

    print("\nResumo:")
    print(f"Linhas no log: {total_linhas}")
    print(f"Linhas com IP valido: {linhas_validas}")

    if not registos_por_pais:
        print("Nao encontrei acessos para montar o mapa.")
        return

    print("\nAcessos agrupados por país:")
    for pais in sorted(registos_por_pais, key=lambda chave: registos_por_pais[chave]["total"], reverse=True):
        info = registos_por_pais[pais]
        print(f"- {pais}: {info['total']} log(s)")

    nome_base_log = os.path.basename(caminho_log) or "log"

    if dados_csv:
        nome_csv = os.path.join(PASTA_RELATORIOS, f"{nome_base_log}_acessos_por_pais.csv")
        with open(nome_csv, "w", newline="", encoding="utf-8") as ficheiro_csv:
            escritor = csv.writer(ficheiro_csv)
            escritor.writerow(["timestamp", "ip", "pais", "latitude", "longitude"])
            for linha in dados_csv:
                escritor.writerow([
                    linha["timestamp"],
                    linha["ip"],
                    linha["pais"],
                    linha["latitude"],
                    linha["longitude"],
                ])
        print(f"\nCSV salvo em: {nome_csv}")

        mapa = folium.Map(location=[0, 0], zoom_start=2)
        for pais, info in registos_por_pais.items():
            coords = info["coordenadas_ip"]
            if not coords:
                continue
            media_lat = sum(coord[0] for coord in coords) / len(coords)
            media_lon = sum(coord[1] for coord in coords) / len(coords)
            descricao = f"{pais} - {info['total']} log(s)"
            folium.Marker(location=[media_lat, media_lon], popup=descricao).add_to(mapa)

        nome_html = os.path.join(PASTA_RELATORIOS, f"{nome_base_log}_acessos_por_pais.html")
        mapa.save(nome_html)
        print(f"Mapa salvo em: {nome_html}")


if __name__ == "__main__":
    main()
