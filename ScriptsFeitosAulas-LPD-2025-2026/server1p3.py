#python version 3
import socket
host = "127.0.0.1" #Server address
port = 12345 #Port of Server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((host,port)) #bind server
s.listen()
(conn, addr) = s.accept()
conn.send("Thank you for connecting".encode())
dataFromClient = conn.recv(1024)
print(dataFromClient.decode())
conn.close()
