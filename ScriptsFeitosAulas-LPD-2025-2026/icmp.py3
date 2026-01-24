#python
import os
response = os.popen('ping -c 1 8.8.8.8')   #GOOGLE
for line in response.readlines():
 print (line)
