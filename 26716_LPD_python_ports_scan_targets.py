#!/usr/bin/env python3
"""Scanner de portas muito simples."""

import socket
import sys

portas_padrao = [22, 80, 443, 3389]
tempo_espera = 0.5


def verificar_porta(host, porta):
	"""Tenta conectar a uma porta e diz se abriu."""
	conexao = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	conexao.settimeout(tempo_espera)
	resultado = conexao.connect_ex((host, porta))
	conexao.close()
	return resultado == 0


def escanear_host(host, lista_portas):
	print(f"\nA verificar {host}...")
	for porta in lista_portas:
		print(f"Testando porta {porta}...", end=" ")
		if verificar_porta(host, porta):
			print("ABERTA")
		else:
			print("fechada")


def main():
	print("Ferramenta simples para descobrir portas abertas")
	hosts_bruto = input("Digite os IPs ou nomes separados por vírgula: ").strip()
	if not hosts_bruto:
		print("Nenhum alvo informado. Encerrando.")
		sys.exit(1)
	lista_hosts = [item.strip() for item in hosts_bruto.split(",") if item.strip()]

	portas_bruto = input(
		"Digite portas separadas por vírgula (Enter usa padrão 21,22,23,25,80,443,587,1433,3389): "
	).strip()
	if portas_bruto:
		try:
			lista_portas = [int(p.strip()) for p in portas_bruto.split(",") if p.strip()]
		except ValueError:
			print("Portas inválidas. Use apenas números.")
			sys.exit(1)
	else:
		lista_portas = portas_padrao

	for host in lista_hosts:
		escanear_host(host, lista_portas)

	print("\nVarredura concluída.")


if __name__ == "__main__":
	main()
