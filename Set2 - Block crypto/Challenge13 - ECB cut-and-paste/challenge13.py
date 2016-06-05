from Crypto.Cipher import AES
import os
import re

BLOCK_SIZE = 16

key = os.urandom(BLOCK_SIZE)
cipher = AES.new(key)

profiles = {}

def parse_cookies(data):
	profile = {}
	entries = data.split('&')

	for entry in entries:
		kv = entry.split('=')

		if len(kv) != 2:
			return None

		k = kv[0]
		v = kv[1]
		profile[k] = v

	return profile

def encode_cookies(profile):
	return "email=%s&uid=%s&role=%s"%(profile['email'], profile['uid'], profile['role'])

def PKCS7_Pad(s):
	return s + chr(BLOCK_SIZE - len(s) % BLOCK_SIZE) * (BLOCK_SIZE - len(s) % BLOCK_SIZE)

def PKCS7_Unpad(s):
	return s.strip(s[-1])

def encrypt_AES(s):
	return cipher.encrypt(PKCS7_Pad(s))

def decrypt_AES(s):
	return PKCS7_Unpad(cipher.decrypt(s))

def profile_for(email):
	email = re.sub("[&=]", "", email)

	if email not in profiles:
		profiles[email] = {'email': email, 'uid': str(len(profiles)), 'role': 'user'}

	return encrypt_AES(encode_cookies(profiles[email]))

def decode_profile(data):
	return parse_cookies(decrypt_AES(data))

admin_block = profile_for("xxxxxxxxxx" + PKCS7_Pad("admin"))[16:32]
encrypted_profile = profile_for("fooikk@bar.com")
modified_data = encrypted_profile[:-16] + admin_block
print decode_profile(modified_data)
