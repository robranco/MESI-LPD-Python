#!/usr/bin/env python3
"""Cliente simples de port knocking para abrir SSH."""

import sys
import time
import subprocess

portas = [4444, 3333, 2222]
pausa = 1


def bater_porta(ip_destino, porta):
	"""Tenta abrir e fechar uma porta rapidamente."""
	print(f"Batendo na porta {porta} do host {ip_destino}...")
	try:
		subprocess.run(
			["nc", "-z", "-w", str(pausa), ip_destino, str(porta)],
#			check=False,
#			stdout=subprocess.DEVNULL,
#			stderr=subprocess.DEVNULL,
		)
	except FileNotFoundError:
		print("O comando nc não foi encontrado.")
		sys.exit(1)


def main():
	print("Cliente de port knocking para abrir SSH")
	servidor_alvo = input(
		"Digite o IP ou domínio do servidor (Enter usa 192.168.1.105): "
	).strip()
	if not servidor_alvo:
		servidor_alvo = "192.168.1.105"

	usuario = input("Digite o usuário para conectar via SSH: ").strip()
	if not usuario:
		print("Nenhum usuário informado. Encerrando.")
		sys.exit(1)

	for porta in portas:
		bater_porta(servidor_alvo, porta)
		time.sleep(pausa)

	print("Sequência completa. Se tudo deu certo do lado do servidor, você tem cerca de 10 segundos para iniciar o SSH.")
	print(f"Exemplo: ssh {usuario}@{servidor_alvo}")


if __name__ == "__main__":
	main()
