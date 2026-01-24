#python version 2
import socket
host = "127.0.0.1" #Server address
port = 12345 #Port of Server
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((host,port)) #bind server
s.listen(2)
conn, addr = s.accept()
print addr, "Ligacao Estabelecida"
conn.send("msg de Servidor para cliente")
conn.close()
