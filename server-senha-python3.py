#python version 3
#Server
import socket
host = "127.0.0.1" #Server address
port = 12345 #Port of Server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((host,port)) #bind server
s.listen()
senha=0
while True:
	(conn, addr) = s.accept()
	conn.send(str(senha).encode())
	dataFromClient = conn.recv(1024)
	print("Senha de cliente atribuída:" + str(senha))
	print(dataFromClient.decode())
	conn.close()
	senha=senha+1