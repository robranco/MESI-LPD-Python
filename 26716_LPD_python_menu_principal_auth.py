#!/usr/bin/env python3
import csv
import getpass
import hashlib
import os
import subprocess
import sys

DEFAULT_MENU_CSV = "26716_LPD_python_menus_opcoes.csv"
DEFAULT_CREDENTIALS_FILE = "26716_LPD_python_credentials.txt"


def ler_opcoes(caminho_csv: str = DEFAULT_MENU_CSV):
	opcoes = []
	with open(caminho_csv, "r", encoding="utf-8") as arquivo:
		leitor = csv.reader(arquivo)
		for linha in leitor:
			if not linha or linha[0] == "numero":
				continue
			opcoes.append({
				"numero": linha[0].strip(),
				"texto": linha[1].strip(),
				"arquivo": linha[2].strip() if len(linha) > 2 else "",
			})
	return opcoes


def mostrar_menu(opcoes):
	print(
		"\nInstrucoes:\n"
		"python3 -m venv .venv\n"
		"source .venv/bin/activate\n"
		"pip install -r requirements.txt.\n"
	)
	while True:
		print("\nMenu principal")
		for item in opcoes:
			print(f"{item['numero']} - {item['texto']}")
		print("0 - Sair")

		escolha = input("Escolha uma opção: ").strip()
		if escolha == "0":
			break

		selecionada = None
		for item in opcoes:
			if item["numero"] == escolha:
				selecionada = item
				break

		if not selecionada:
			print("Opção inválida.")
			continue

		caminho = selecionada["arquivo"]
		if not caminho:
			print("Esta opção não tem script ligado.")
			continue
		if not os.path.exists(caminho):
			print(f"Arquivo {caminho} não encontrado.")
			continue

		print(f"Executando {caminho}...")
		subprocess.run([sys.executable, caminho], check=False)


def carregar_credenciais(caminho_credenciais: str = DEFAULT_CREDENTIALS_FILE):
	if not os.path.isfile(caminho_credenciais):
		raise FileNotFoundError("Arquivo de credenciais nao encontrado.")

	with open(caminho_credenciais, "r", encoding="utf-8") as arquivo:
		leitor = csv.reader(arquivo)
		for linha in leitor:
			if not linha:
				continue
			if len(linha) < 2:
				continue
			usuario = linha[0].strip()
			hash_senha = linha[1].strip()
			if usuario and hash_senha:
				return usuario, hash_senha

	raise ValueError("Arquivo de credenciais invalido.")

def autenticar_usuario(caminho_credenciais: str = DEFAULT_CREDENTIALS_FILE):
	try:
		usuario, hash_esperado = carregar_credenciais(caminho_credenciais)
	except FileNotFoundError:
		print(f"Arquivo de credenciais nao encontrado. Crie {caminho_credenciais}.")
		return False
	except ValueError as erro:
		print(f"Erro ao ler credenciais: {erro}")
		return False

	usuario_informado = input("Usuario: ").strip()
	usuario_hash = hashlib.sha512(usuario_informado.encode("utf-8")).hexdigest()
	if usuario_hash != usuario:
		print("Usuario nao encontrado.")
		return False

	senha = getpass.getpass("Senha: ")
	hash_digitado = hashlib.sha512(senha.encode("utf-8")).hexdigest()
	if hash_digitado == hash_esperado:
		print("Autenticacao bem-sucedida.\n")
		return True

	print("Senha incorreta. Acesso negado.")
	return False


def main(argv=None):
	"""Executa o menu autenticado permitindo configurar os arquivos via argumentos."""
	argv = [] if argv is None else list(argv)
	caminho_csv = DEFAULT_MENU_CSV if not argv else argv[0]
	caminho_credenciais = DEFAULT_CREDENTIALS_FILE if len(argv) < 2 else argv[1]
	try:
		opcoes = ler_opcoes(caminho_csv)
	except FileNotFoundError:
		print("Arquivo CSV de menu não encontrado.")
		return
	if not opcoes:
		print("O menu está vazio.")
		return
	if not autenticar_usuario(caminho_credenciais):
		return

	mostrar_menu(opcoes)
	print("Programa encerrado.")


if __name__ == "__main__":
	main(sys.argv[1:])
