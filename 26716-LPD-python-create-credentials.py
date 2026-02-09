#!/usr/bin/env python3
"""Gera hashes SHA-512 para usuario e senha e grava no ficheiro de credenciais."""

import getpass
import hashlib
from pathlib import Path

ARQUIVO_CREDENCIAIS = Path("26716-LPD-python-credentials.txt")


def gerar_hash(texto: str) -> str:
    return hashlib.sha512(texto.encode("utf-8")).hexdigest()


def main() -> None:
    print("Gerador de credenciais (hash SHA-512)")
    username = input("Informe o usuario: ").strip()
    if not username:
        print("Usuario invalido. Abortado.")
        return

    password = getpass.getpass("Informe a senha: ")
    if not password:
        print("Senha vazia. Abortado.")
        return

    username_hash = gerar_hash(username)
    password_hash = gerar_hash(password)

    ARQUIVO_CREDENCIAIS.write_text(f"{username_hash},{password_hash}\n", encoding="utf-8")
    print(f"Credenciais gravadas em {ARQUIVO_CREDENCIAIS}.")


if __name__ == "__main__":
    main()
