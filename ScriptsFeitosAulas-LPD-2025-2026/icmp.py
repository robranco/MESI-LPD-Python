#python
import os
ip = input('Insira IP: ')
status = 'ligado'

response = os.popen('ping -c 1 ' + ip)   #GOOGLE
for line in response.readlines():
 #print line
 if '100%' in line:
  status = 'desligado'

print (status)
