#!/usr/bin/env python3
"""Mostra informacoes basicas das bases MaxMind (GeoLite2) colocadas na pasta maxmind/."""

from datetime import datetime, timezone
from pathlib import Path

import geoip2.database

BASE_DIR = Path(__file__).resolve().parent
MAXMIND_DIR = BASE_DIR / "maxmind"
BANCOS = [
    (MAXMIND_DIR / "GeoLite2-City.mmdb", "GeoLite2 City"),
    (MAXMIND_DIR / "GeoLite2-Country.mmdb", "GeoLite2 Country"),
]


def obter_metadata(reader):
    meta = reader.metadata
    tentativas = 0
    while callable(meta) and tentativas < 3:
        meta = meta()
        tentativas += 1
    if not hasattr(meta, "build_epoch"):
        raise AttributeError("metadata nao possui build_epoch")
    return meta


def formatar_meta(reader):
    meta = obter_metadata(reader)
    data = datetime.fromtimestamp(meta.build_epoch, timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )
    return {
        "tipo": meta.database_type,
        "versao_bin": f"{meta.binary_format_major_version}.{meta.binary_format_minor_version}",
        "build": data,
        "idiomas": ", ".join(meta.languages),
    }


def mostrar_info(caminho, descricao):
    if not caminho.exists():
        print(f"[!] {descricao}: arquivo {caminho} nao encontrado.")
        return
    try:
        with geoip2.database.Reader(caminho) as reader:
            meta = formatar_meta(reader)
            print(f"[*] {descricao} -> tipo: {meta['tipo']}")
            print(f"    build: {meta['build']} | formato: {meta['versao_bin']}")
            print(f"    idiomas: {meta['idiomas'] or 'n/d'}")
    except Exception as exc:
        print(f"[!] Erro ao ler {descricao}: {exc}")


def main():
    for caminho, descricao in BANCOS:
        mostrar_info(caminho, descricao)


if __name__ == "__main__":
    main()
