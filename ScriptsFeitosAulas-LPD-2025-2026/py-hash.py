import hashlib

pass1 = 'hello'

mpass1 = hashlib.sha512(pass1.encode('UTF-8'))
print(mpass1.hexdigest())

#Retorna True or False
def check_password(clear_password, password_hash):
    #print (hashlib.sha512(clear_password.encode('UTF-8')).hexdigest())
    return hashlib.sha512(clear_password.encode('UTF-8')).hexdigest() == password_hash


print (check_password(pass1,"c70b5dd9ebfb6f51d09d4132b7170c9d20750a7852f00680f65658f0310e810056e6763c34c9a00b0e940076f54495c169fc2302cceb312039271c43469507dc"))
#ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"))
