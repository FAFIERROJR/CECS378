import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def Myencrypt(message, key):
	if len(key) < 32:
		return -1

	iv = os.urandom(16)

	backend = default_backend()
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
	encryptor = cipher.encryptor()
	padder = padding.PKCS7(128).padder()

	padded_message = padder.update(message.encode()) + padder.finalize()

	ciphertext = encryptor.update(padded_message) + encryptor.finalize()
	return (ciphertext, iv)

def MyfileEncrypt(filepath):
	key = os.urandom(32)
	file = open(filepath, "r")
	filename, file_extension = os.path.splitext(filepath)
	message = file.read()

	ciphertext, iv = Myencrypt(message, key)
	return (ciphertext, iv, key, file_extension)


#def MyRSAEncrypt(filepath, RSA_Publickey_filepath):




