#file = open("log.txt", "append")
#file.write("**********\n")
#file.write("http log 2\n")

#file.close()
file = open("log.txt", "r")
for line in file:
    print line
