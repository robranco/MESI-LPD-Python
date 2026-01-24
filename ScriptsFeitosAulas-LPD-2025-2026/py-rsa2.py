from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Gerar chaves public e private RSA
key = RSA.generate(2048)
private_key = key
public_key = key.publickey()

print (key.export_key())   # print chave privada
print (key.publickey().export_key())   # print chave pública

# Criar a cifra com a chave pública OAEP (Optimal Asymmetric Encryption Padding)

cipher_rsa = PKCS1_OAEP.new(public_key)

# Mensagem para encriptar
msg = "Linguagem de Programação Dinâmica"
msg_bytes = msg.encode('utf-8')

#  Encriptar Mensagem
msg_encriptada = cipher_rsa.encrypt(msg_bytes)
print("Mensagem encriptada (bytes):", msg_encriptada)

# Desencriptar Mensagem
decipher_rsa = PKCS1_OAEP.new(private_key)
msg_desencriptada = decipher_rsa.decrypt(msg_encriptada)

print("\nMensagem original: ", msg)
print("Mensagem desencriptada:", msg_desencriptada.decode('utf-8'))
