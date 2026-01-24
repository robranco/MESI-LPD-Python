from Crypto.Cipher import AES

#Encriptar
data = b"OLA alunos, mensagem confidencial"
key = b"0223456701234567"  # chave com 16 caracteres
cipher = AES.new(key, AES.MODE_EAX)

nonce = cipher.nonce
ciphertext, tag = cipher.encrypt_and_digest(data)

print (ciphertext)

#Desencriptar
key = b"0223456701234567"
cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
plaintext = cipher.decrypt(ciphertext)

print (plaintext)
