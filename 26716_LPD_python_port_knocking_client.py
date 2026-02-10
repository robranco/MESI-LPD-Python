#!/usr/bin/env python3
"""Cliente simples de port knocking para abrir SSH."""

import sys
import time
import subprocess

portas = [4444, 3333, 2222]
pausa = 1


def _extrair_parametros(argv):
	argumentos = argv if argv is not None else sys.argv[1:]
	servidor = None
	usuario = None
	if argumentos:
		servidor = argumentos[0].strip() or None
		if len(argumentos) > 1:
			usuario = argumentos[1].strip() or None
	return servidor, usuario


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


def main(argv=None):
	print("Cliente de port knocking para abrir SSH")
	servidor_cli, usuario_cli = _extrair_parametros(argv)

	servidor_alvo = servidor_cli or input(
		"Digite o IP ou domínio do servidor (Enter usa 192.168.1.105): "
	).strip()
	if not servidor_alvo:
		servidor_alvo = "192.168.1.105"

	usuario = usuario_cli or input("Digite o usuário para conectar via SSH: ").strip()
	if not usuario:
		print("Nenhum usuário informado. Encerrando.")
		sys.exit(1)

	for porta in portas:
		bater_porta(servidor_alvo, porta)
		time.sleep(pausa)

	print("Sequência completa. Se tudo deu certo do lado do servidor, você tem cerca de 10 segundos para iniciar o SSH.")
	print(f"Exemplo: ssh {usuario}@{servidor_alvo}")


if __name__ == "__main__":
	main(sys.argv[1:])
