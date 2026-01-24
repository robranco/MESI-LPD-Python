#python 2
#client
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
host = "127.0.0.1" # server address
port =12345 #server port
s.connect((host,port))
senha = s.recv(1024)
print ("A minha senha e:" + senha )
#print s.recv(1024)
s.send("Resposta Cliente com senha numero " + senha)
s.close()
