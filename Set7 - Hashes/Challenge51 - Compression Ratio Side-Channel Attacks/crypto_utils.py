from Crypto.Cipher import AES

BLOCK_SIZE = 16

def PKCS7_Pad(s):
	return s + chr(BLOCK_SIZE - len(s) % BLOCK_SIZE) * (BLOCK_SIZE - len(s) % BLOCK_SIZE)

def PKCS7_Unpad(s):
	return s.strip(s[-1])

def aes_cbc_encrypt(msg, key, iv):
	cipher = AES.new(key)
	result = ""
	cipher_block = "".join([c for c in iv])

	for block in range(len(msg) / BLOCK_SIZE):
		cipher_block = "".join([chr(ord(cipher_block[i]) ^ ord(msg[block * BLOCK_SIZE + i])) for i in range(BLOCK_SIZE)])
		cipher_block = cipher.encrypt(cipher_block)
		result += cipher_block
	
	return result
