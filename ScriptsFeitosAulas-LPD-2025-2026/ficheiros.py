
file = open("ficheiro1", "w")
LinhasDoTexto = ["frase 1", "frase 2", "frase 3"]
file.writelines(LinhasDoTexto)
file.close()




file = open("ficheiro.txt", "r")
data = file.readlines()
for line in data:
 words = line.split()
 print (words)
