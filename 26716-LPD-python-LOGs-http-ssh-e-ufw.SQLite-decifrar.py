#!/usr/bin/env python3
"""Abre um arquivo texto protegido por hash e exibe seu conteudo."""

import base64
import getpass
import hashlib
import sqlite3
from pathlib import Path

try:
    from Crypto.Cipher import AES
except ImportError:
    print("pycryptodome nao encontrado. Instale com 'pip install pycryptodome'.")
    raise

def _derivar_chave(senha: str) -> bytes:
    return hashlib.sha256(senha.encode("utf-8")).digest()


def _decifrar_texto(bloco_base64: str, chave: bytes) -> str:
    dados = base64.b64decode(bloco_base64)
    nonce, tag, cifrado = dados[:12], dados[12:28], dados[28:]
    cifra = AES.new(chave, AES.MODE_GCM, nonce=nonce)
    texto = cifra.decrypt_and_verify(cifrado, tag)
    return texto.decode("utf-8", errors="ignore")


def main():
    caminho = input("Informe o caminho do ficheiro SQLite cifrado: ").strip()
    if not caminho:
        print("Arquivo nao informado. Saindo.")
        return

    senha = getpass.getpass("Senha: ")
    if not senha:
        print("Senha vazia. Saindo.")
        return

    chave = _derivar_chave(senha)

    try:
        conexao = sqlite3.connect(caminho)
    except sqlite3.Error as erro:
        print(f"Nao foi possivel abrir o SQLite: {erro}")
        return

    with conexao:
        cursor = conexao.cursor()
        cursor.execute(
            "SELECT timestamp_cifrado, ip_cifrado, country_cifrado, city_cifrado FROM acessos"
        )
        registos = cursor.fetchall()

    if not registos:
        print("Nenhum registro encontrado na tabela acessos.")
        return

    print("\n--- Registos decifrados ---")
    for idx, (ts, ip, country, city) in enumerate(registos, start=1):
        print(f"\nRegistro {idx}:")
        print(f"  Timestamp: {_decifrar_texto(ts, chave)}")
        print(f"  IP: {_decifrar_texto(ip, chave)}")
        print(f"  Pais: {_decifrar_texto(country, chave)}")
        print(f"  Cidade: {_decifrar_texto(city, chave)}")

if __name__ == "__main__":
    main()
