# -*- coding: utf-8 -*-
"""
Encryption and Decryption methods
Created on Thu Oct 26 14:11:51 2017

@authors: Francisco Fierro and Daniel Wang
"""

import os
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as apadding
from cryptography.hazmat.primitives.asymmetric import rsa

def MydecryptMAC(ciphertext, tag, EncKey, HMACKey, iv):
	if len(EncKey) < 32:
		print("Encryption key is not 32 bytes")
		return -1

	if len(iv) < 16:
		print("IV is not 16 bytes")
		return -1

	h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
	h.update(ciphertext)
	new_tag = h.finalize()

	if(tag == new_tag):
		print("tags match!")
		backend = default_backend()
		cipher = Cipher(algorithms.AES(EncKey), modes.CBC(iv), backend=backend)
		decryptor = cipher.decryptor()
		unpadder = padding.PKCS7(128).unpadder()


		padded_message= decryptor.update(ciphertext) + decryptor.finalize()

		byte_message = unpadder.update(padded_message) + unpadder.finalize()

		return byte_message
	else:
		print("Tags do not match!!!")


def MyencryptMAC(message, EncKey, HMACKey):
	if len(EncKey) < 32:
		return -1

	iv = os.urandom(16)

	backend = default_backend()
	cipher = Cipher(algorithms.AES(EncKey), modes.CBC(iv), backend=backend)
	encryptor = cipher.encryptor()
	padder = padding.PKCS7(128).padder()

	if(type(message) == str):
		encoded_message = message.encode("utf-8")
	else:
		encoded_message = message

	padded_message = padder.update(encoded_message) + padder.finalize()

	ciphertext = encryptor.update(padded_message) + encryptor.finalize()

	h = hmac.HMAC(HMACKey, hashes.SHA256(), backend=default_backend())
	h.update(ciphertext)
	tag = h.finalize()

	return ciphertext, iv, tag

def MyfileEncryptMAC(filepath):
	EncKey = os.urandom(32)
	HMACKey = os.urandom(128)
	filename, file_extension = os.path.splitext(filepath)

	if(file_extension == ".txt"):
		file = open(filepath, "r")
	else:
		file = open(filepath, "rb")

	message = file.read()
	ciphertext, iv, tag = MyencryptMAC(message, EncKey, HMACKey)

	#file_data = ciphertext

	#new_file = open(filename , "wb")
	
	#new_file.write(file_data)
	return ciphertext, iv, tag, EncKey, HMACKey, file_extension

def MyfileDecryptMAC(filepath, Enckey, HMACKey, ciphertext, iv, tag, file_extension):
	#file = open(filepath, "rb")
	#ciphertext = file.read()

	file_data = MydecryptMAC(ciphertext, tag, Enckey, HMACKey, iv)
	filename = filepath + file_extension
	
	if(file_extension != ".txt"):
		file = open(filename, "wb")
	else:
		file = open(filename, "w")
		file_data = file_data.decode("utf-8")

	file.write(file_data)



def MyRSAEncrypt(filepath, RSA_publickey_filepath):
	ciphertext, iv, tag, EncKey, HMACKey, file_extension = MyfileEncryptMAC(filepath)

	with open(RSA_publickey_filepath, "rb") as key_file:
		public_key = serialization.load_pem_public_key(
				key_file.read(),
				backend=default_backend()
				)

	keys = EncKey + HMACKey

	RSACipher = public_key.encrypt(
		keys,
		apadding.OAEP(
			mgf=apadding.MGF1(algorithm=hashes.SHA256()),
			algorithm=hashes.SHA256(),
			label=None
		)
	)

	return RSACipher, ciphertext, iv, tag, file_extension

def MyRSADecrypt(filepath, RSACipher, ciphertext, iv, tag, file_extension, RSA_privatekey_filepath):

	# load the private key
	with open(RSA_privatekey_filepath, "rb") as key_file:
		private_key = serialization.load_pem_private_key(
				key_file.read(),
				password=None,
				backend=default_backend()
				)
	# use the private key to decrypt the RSA encrypted AES key
	keys = private_key.decrypt(
			RSACipher,
			apadding.OAEP(
					mgf=apadding.MGF1(algorithm=hashes.SHA256()),
					algorithm=hashes.SHA256(),
					label=None
					)
			)

	EncKey = keys[0:32]
	HMACKey = keys[32:]

	# decrypt with keys
	MyfileDecryptMAC(filepath, EncKey, HMACKey, ciphertext, iv, tag, file_extension)

def genRSAkeys():
	private_key = rsa.generate_private_key(
	public_exponent=65537,
	key_size=2048,
	backend=default_backend()
	)

	pem = private_key.private_bytes(
	encoding=serialization.Encoding.PEM,
	format=serialization.PrivateFormat.PKCS8,
	encryption_algorithm=serialization.NoEncryption()
	)

	file = open("RSA_PrivateKey", "wb")
	file.write(pem)

	public_key = private_key.public_key()

	pem = public_key.public_bytes(
	encoding=serialization.Encoding.PEM,
	format=serialization.PublicFormat.SubjectPublicKeyInfo,
	)

	file = open("RSA_PublicKey", "wb")
	file.write(pem)

def checkRSAKeys():
	private_key_name = "RSA_PrivateKey"
	public_key_name = "RSA_PublicKey"
	files = os.listdir(os.curdir)
	keys_present = [False, False]

	for f in files:
		if(f == private_key_name):
			print("found RSA private key")
			keys_present[0] = True
		if(f == public_key_name):
			print("found RSA public key")
			keys_present[1] = True

	if(keys_present[0] and keys_present[1]):
		print("RSA keys are present. No need to generate")
		return True
	else:
		print("RSA key(s) missing. Generating keys...")
		return False
