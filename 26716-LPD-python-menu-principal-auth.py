#!/usr/bin/env python3
import csv
import getpass
import hashlib
import os
import subprocess
import sys

arquivo_csv = "26716-LPD-python-menus-opcoes.csv"
CREDENCIAIS_ARQUIVO = "26716-LPD-python-credentials.txt"


def ler_opcoes():
	opcoes = []
	with open(arquivo_csv, "r", encoding="utf-8") as arquivo:
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


def carregar_credenciais():
	if not os.path.isfile(CREDENCIAIS_ARQUIVO):
		raise FileNotFoundError("Arquivo de credenciais nao encontrado.")

	with open(CREDENCIAIS_ARQUIVO, "r", encoding="utf-8") as arquivo:
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


def autenticar_usuario():
	try:
		usuario, hash_esperado = carregar_credenciais()
	except FileNotFoundError:
		print("Arquivo de credenciais nao encontrado. Crie 26716-LPD-python-credentials.txt.")
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


def main():
	try:
		opcoes = ler_opcoes()
	except FileNotFoundError:
		print("Arquivo CSV de menu não encontrado.")
		return
	if not opcoes:
		print("O menu está vazio.")
		return
	if not autenticar_usuario():
		return

	mostrar_menu(opcoes)
	print("Programa encerrado.")


if __name__ == "__main__":
	main()
