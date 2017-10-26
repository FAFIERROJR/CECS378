import encryptipy as enpy
import os

key = os.urandom(32)
ciphertext, iv = enpy.Myencrypt("Hello, World!", key)

print(ciphertext)
print(iv)

message = enpy.Mydecrypt(ciphertext, key, iv)
print(message)

ciphertext, iv, key , file_extension = enpy.MyfileEncrypt("dog.jpg")

print(ciphertext)
print(iv)
print(key)
print(file_extension)

enpy.MyfileDecrypt("encryptedfile" + file_extension, key, iv, file_extension)

key, ciphertext, iv, file_extension = enpy.MyRSAEncrypt("dog.jpg", "RSA_Public_key")

print(ciphertext)
print(iv)
print(key)
print(file_extension)
