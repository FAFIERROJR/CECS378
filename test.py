import encryptipy as enpy
import os

key = os.urandom(32)
ciphertext, iv = enpy.Myencrypt("Hello, World!", key)

print(ciphertext)
print(iv)

message = enpy.Mydecrypt(ciphertext, key, iv)
print(message)

ciphertext, iv, key , file_extension = enpy.MyfileEncrypt("testtext.txt")

print(ciphertext)
print(iv)
print(key)
print(file_extension)

enpy.MyfileDecrypt(ciphertext, key, iv, file_extension)