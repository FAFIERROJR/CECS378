import encryptipy as enpy
import os

key = os.urandom(32)
ciphertext, iv = enpy.Myencrypt("Hello, World!", key)

print(ciphertext)
print(iv)

ciphertext, iv, key , file_extension = enpy.MyfileEncrypt("testtext.txt")

print(ciphertext)
print(iv)
print(key)
print(file_extension)