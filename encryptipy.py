import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

def Mydecrypt(ciphertext, key, iv):
	if len(key) < 32:
		return -1

	if len(iv) < 16:
		return -1

	backend = default_backend()
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
	decryptor = cipher.decryptor()
	unpadder = padding.PKCS7(128).unpadder()


	padded_message= decryptor.update(ciphertext) + decryptor.finalize()

	byte_message = unpadder.update(padded_message) + unpadder.finalize()
	byte_message = byte_message
	
	return byte_message


def Myencrypt(message, key):
	if len(key) < 32:
		return -1

	iv = os.urandom(16)

	backend = default_backend()
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
	encryptor = cipher.encryptor()
	padder = padding.PKCS7(128).padder()

	if(type(message) == str):
		encoded_message = message.encode("utf-8")
	else:
		encoded_message = message

	padded_message = padder.update(encoded_message) + padder.finalize()

	ciphertext = encryptor.update(padded_message) + encryptor.finalize()

	return ciphertext, iv

def MyfileEncrypt(filepath):
	key = os.urandom(32)
	filename, file_extension = os.path.splitext(filepath)

	if(file_extension == ".txt"):
		file = open(filepath, "r")
	else:
		file = open(filepath, "rb")

	message = file.read()
	print(message)
	ciphertext, iv = Myencrypt(message, key)

	file_data = ciphertext

	new_file = open("encryptedfile" + file_extension, "wb")
	
	new_file.write(file_data)
	return ciphertext, iv, key, file_extension

def MyfileDecrypt(filepath, key, iv, file_extension):
	file = open(filepath, "rb")
	ciphertext = file.read()

	file_data = Mydecrypt(ciphertext, key, iv)
	filename = "decryptedfile" + file_extension
	
	if(file_extension != ".txt"):
		file = open(filename, "wb")
	else:
		file = open(filename, "w")
		file_data = file_data.decode("utf-8")

	file.write(file_data)



def MyRSAEncrypt(filepath, RSA_Publickey_filepath):
	ciphertext, iv, AES_key, file_extension = MyfileEncrypt(filepath)

	RSA_key_file = open(RSA_Publickey_filepath)
	public_key = serialization.load_pem_public_key(RSA_key_file, backend=default_backend())
	AES_key_ciphertext = public_key.encrypt(
		AES_key,
		padding.OAEP(
			mgf=padding.MGF1(algorithm=hashes.SHA1()),
			algorithm=hashes.SHA1(),
			label=None
		)
	)

	return AES_key_ciphertext, ciphertext, iv, file_extension

