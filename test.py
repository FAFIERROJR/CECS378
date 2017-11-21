import encryptipy as enpy
import os

if(enpy.checkRSAKeys() == False):
    enpy.genRSAkeys()

original_file_path = "dog.jpg"
encrypted_file_path = "dog"
RSA_public_key_path = "RSA_PublicKey"
RSA_private_key_path = "RSA_PrivateKey"


RSA_cipher, ciphertext, iv, tag, file_extension = enpy.MyRSAEncrypt(original_file_path, RSA_public_key_path)

enpy.MyRSADecrypt(RSA_cipher, encrypted_file_path, iv, tag, file_extension, RSA_private_key_path)