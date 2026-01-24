#!/usr/bin/env python3
"""Script simples que usa ssh/scp nativos para copiar um arquivo com sudo remoto."""

import getpass
import os
import subprocess
import sys


def mostrar_uso() -> None:
	print(
		"Uso: python3 fetch-live-log-files-from-remote-server.py "
		"<servidor> <usuario> <arquivo_remoto> [arquivo_local]"
	)
	sys.exit(1)


def executar_ssh_com_sudo(servidor: str, usuario: str, senha: str, comando: str) -> bool:
	instrucao = ["ssh", f"{usuario}@{servidor}", "sudo", "-S", "sh", "-c", comando]
	resultado = subprocess.run(
		instrucao,
		input=senha + "\n",
		text=True,
		capture_output=True,
	)
	if resultado.stderr.strip():
		print(resultado.stderr.strip())
	return resultado.returncode == 0


def main() -> None:
	if len(sys.argv) < 4:
		mostrar_uso()

	servidor = sys.argv[1]
	usuario = sys.argv[2]
	arquivo_remoto = sys.argv[3]
	arquivo_local = sys.argv[4] if len(sys.argv) > 4 else arquivo_remoto.split("/")[-1]

	senha = getpass.getpass(f"Informe a senha do usuário {usuario}: ")
	arquivo_tmp = f"/tmp/copiar_{os.getpid()}"

	print("Preparando arquivo temporário com sudo no servidor...")
	comando_prep = (
		f"cp {arquivo_remoto} {arquivo_tmp} && chmod 600 {arquivo_tmp} "
		f"&& chown {usuario} {arquivo_tmp}"
	)
	if not executar_ssh_com_sudo(servidor, usuario, senha, comando_prep):
		print("Não foi possível preparar o arquivo remoto.")
		sys.exit(1)

	print("Copiando arquivo via scp nativo...")
	scp_cmd = ["scp", f"{usuario}@{servidor}:{arquivo_tmp}", arquivo_local]
	scp_result = subprocess.run(scp_cmd)
	if scp_result.returncode != 0:
		print("scp falhou. Abortando.")
		executar_ssh_com_sudo(servidor, usuario, senha, f"rm -f {arquivo_tmp}")
		sys.exit(1)

	print(f"Arquivo copiado para {arquivo_local}. Limpando arquivo temporário...")
	executar_ssh_com_sudo(servidor, usuario, senha, f"rm -f {arquivo_tmp}")
	print("Operação concluída.")


if __name__ == "__main__":
	main()
