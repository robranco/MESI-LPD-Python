#!/usr/bin/env python3
import csv
import os
import subprocess
import sys

arquivo_csv = "26716-LPD-python-menus-opcoes.csv"


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


def main():
	try:
		opcoes = ler_opcoes()
	except FileNotFoundError:
		print("Arquivo CSV de menu não encontrado.")
		return
	if not opcoes:
		print("O menu está vazio.")
		return
	mostrar_menu(opcoes)
	print("Programa encerrado.")


if __name__ == "__main__":
	main()
