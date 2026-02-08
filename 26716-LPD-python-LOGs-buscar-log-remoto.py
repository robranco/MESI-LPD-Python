#!/usr/bin/env python3
import base64
import gzip
import hashlib
import os
import re
import shutil
import subprocess
from datetime import datetime
from getpass import getpass
from shlex import quote


SSH_OPCOES = [
    "-o", "StrictHostKeyChecking=accept-new"
]


def sanitizar_texto_para_nome(texto):
    """Mantém apenas caracteres seguros para compor nomes de arquivos."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", texto)


def caminho_para_nome_arquivo(caminho):
    caminho = caminho.strip()
    if caminho.startswith("/"):
        caminho = caminho[1:]
    return caminho.replace("/", "-")


def calcular_sha256(caminho):
    sha256 = hashlib.sha256()
    with open(caminho, "rb") as arquivo:
        for bloco in iter(lambda: arquivo.read(65536), b""):
            sha256.update(bloco)
    return sha256.hexdigest()


def ler_hash_arquivo(caminho):
    try:
        with open(caminho, "r", encoding="utf-8") as arquivo:
            conteudo = arquivo.read().strip()
    except FileNotFoundError:
        return None

    if not conteudo:
        return None

    return conteudo.split()[0]


def extrair_gzip(origem_gzip, destino_final):
    with gzip.open(origem_gzip, "rb") as arquivo_gzip, open(destino_final, "wb") as destino:
        shutil.copyfileobj(arquivo_gzip, destino)


def remover_arquivos_locais(*caminhos):
    for caminho in caminhos:
        try:
            os.remove(caminho)
        except FileNotFoundError:
            continue


def remover_temporarios_remotos(senha, usuario, servidor, caminhos):
    caminhos_validos = [c for c in caminhos if c]
    if not caminhos_validos:
        return

    comando = f"rm -f {' '.join(caminhos_validos)}"
    if not executar_comando(montar_cmd_ssh(senha, usuario, servidor, comando)):
        print("\nAviso: não consegui remover os temporários no servidor.")


def montar_script_preparacao(senha, caminho_remoto, nome_tmp):
    senha_b64 = base64.b64encode((senha + "\n").encode("utf-8")).decode("ascii")
    caminho_segmentado = quote(caminho_remoto)
    return f"""
set -euo pipefail
PASS_B64='{senha_b64}'
SUDO_PASS="$(printf '%s' "$PASS_B64" | base64 -d)"
run_sudo() {{
  printf '%s\n' "$SUDO_PASS" | sudo -S "$@"
}}

ARQUIVO={caminho_segmentado}
TMP="$HOME/{nome_tmp}"

run_sudo cp "$ARQUIVO" "$TMP"
run_sudo chown "$USER:$USER" "$TMP"
run_sudo chmod 600 "$TMP"

gzip -f "$TMP"
sha256sum "$TMP.gz" > "$TMP.gz.sha256sum.txt"
"""


def executar_comando(comando, entrada=None):
    try:
        subprocess.run(
            comando,
            input=entrada,
            text=True,
            capture_output=True,
            check=True
        )
        return True
    except FileNotFoundError:
        print("\nComando não encontrado:")
        print(" ".join(comando))
    except subprocess.CalledProcessError as err:
        print("\nFalha ao executar:")
        print(" ".join(comando))
        if err.stdout and err.stdout.strip():
            print("\nSaída:")
            print(err.stdout.strip())
        if err.stderr and err.stderr.strip():
            print("\nErro:")
            print(err.stderr.strip())
    return False


def montar_cmd_ssh(senha, usuario, servidor, comando_remoto):
    return [
        "sshpass", "-p", senha,
        "ssh", *SSH_OPCOES,
        f"{usuario}@{servidor}",
        comando_remoto
    ]


def montar_cmd_scp(senha, usuario, servidor, origem_remota, destino_local):
    return [
        "sshpass", "-p", senha,
        "scp", *SSH_OPCOES,
        f"{usuario}@{servidor}:{origem_remota}",
        destino_local
    ]


def verificar_sshpass():
    if shutil.which("sshpass") is None:
        print("\nERRO: o utilitário 'sshpass' não foi encontrado no PATH.")
        print("Instale-o antes de executar este script (ex.: sudo apt install sshpass).")
        return False
    return True


def main():
    if not verificar_sshpass():
        return

    print("=== Download de arquivo remoto com sudo (ssh/scp) ===")

    servidor = input("Servidor (IP ou DNS): ").strip()
    usuario = input("Usuário SSH: ").strip()
    caminho_remoto = input("Caminho do arquivo (ex: /var/log/auth.log): ").strip()
    senha_total = getpass("Senha SSH (também usada para sudo): ")

    diretorio_local = input("Diretório local para salvar (ex: ./baixados): ").strip()
    if not diretorio_local:
        diretorio_local = "./baixados"

    os.makedirs(diretorio_local, exist_ok=True)

    nome_original = os.path.basename(caminho_remoto)
    nome_tmp = sanitizar_texto_para_nome(nome_original or "arquivo-temporario")

    caminho_plain_user = f"~/{nome_tmp}"
    caminho_gz_user = f"{caminho_plain_user}.gz"
    caminho_sha_user = f"{caminho_gz_user}.sha256sum.txt"

    instante = datetime.now().strftime("%Y-%m-%d-%H-%M")
    nome_servidor = sanitizar_texto_para_nome(servidor)
    caminho_convertido = caminho_para_nome_arquivo(caminho_remoto)
    nome_base_local = f"{instante}-{nome_servidor}-{caminho_convertido}"
    caminho_local_final = os.path.join(diretorio_local, nome_base_local)
    caminho_local_gz = f"{caminho_local_final}.gz"
    caminho_local_sha = f"{caminho_local_gz}.sha256sum.txt"

    caminhos_remotos = [caminho_plain_user, caminho_gz_user, caminho_sha_user]

    try:
        print("\n[1/4] Preparando, compactando e gerando SHA-256 no servidor...")

        script_remoto = montar_script_preparacao(senha_total, caminho_remoto, nome_tmp)
        comando_script = [
            "sshpass", "-p", senha_total,
            "ssh", *SSH_OPCOES,
            f"{usuario}@{servidor}",
            "bash", "-s"
        ]

        if not executar_comando(comando_script, entrada=script_remoto):
            print("\nNão foi possível preparar os arquivos no servidor.")
            return

        print("\n[2/4] Baixando o arquivo compactado (.gz)...")
        if not executar_comando(
            montar_cmd_scp(senha_total, usuario, servidor, caminho_gz_user, caminho_local_gz)
        ):
            print("\nFalha no scp do arquivo compactado.")
            remover_arquivos_locais(caminho_local_gz)
            return

        print("\n[3/4] Baixando o arquivo de verificação (.sha256sum.txt)...")
        if not executar_comando(
            montar_cmd_scp(senha_total, usuario, servidor, caminho_sha_user, caminho_local_sha)
        ):
            print("\nFalha ao baixar o arquivo de hash. Removendo arquivos locais temporários.")
            remover_arquivos_locais(caminho_local_gz, caminho_local_sha)
            return

        print("\n[4/4] Validando hash e extraindo o arquivo original...")
        hash_esperado = ler_hash_arquivo(caminho_local_sha)
        if not hash_esperado:
            print("\nNão foi possível ler o hash esperado. Abortando.")
            remover_arquivos_locais(caminho_local_gz, caminho_local_sha)
            return

        hash_local = calcular_sha256(caminho_local_gz)

        if hash_local != hash_esperado:
            print("\nERRO: hash SHA-256 divergente! Download pode estar corrompido.")
            remover_arquivos_locais(caminho_local_gz, caminho_local_sha)
            return

        try:
            extrair_gzip(caminho_local_gz, caminho_local_final)
        except OSError as err:
            print("\nNão consegui extrair o arquivo compactado:")
            print(str(err))
            return

        remover_arquivos_locais(caminho_local_gz, caminho_local_sha)
        print("\nSucesso! Arquivo validado e salvo em:")
        print(caminho_local_final)

    finally:
        remover_temporarios_remotos(senha_total, usuario, servidor, caminhos_remotos)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperação cancelada pelo usuário.")
