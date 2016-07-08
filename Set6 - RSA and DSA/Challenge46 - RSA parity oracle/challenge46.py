import base64
import sys

import crypto_utils as utils

class Server(object):
	def __init__(self):
		message = base64.b64decode("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==")
		self.e = 65537
		self.n, self.d = utils.gen_private_key(1024, self.e)
		self.ciphertext = utils.RSA_encrypt(message, self.n, self.e)
	
	def get_ciphertext(self):
		return self.ciphertext

	def get_public_key(self):
		return self.n, self.e

	def parity_oracle(self, cipher):
		msg = utils.RSA_decrypt(cipher, self.n, self.d)

		if ord(msg[-1]) & 0x01 == 0:
			return True

		return False

def to_printable(string):
	res = ""

	for c in string:
		if ord(c) >= 32 and ord(c) <= 126:
			res += c
		else:
			res += "\\x" + str(c).encode('hex')
	
	return res

def double_plaintext(cipher, n, e):
	c = utils.string_to_integer(cipher)
	c = (c * pow(2, e, n)) % n
	return utils.integer_to_string(c)

def crack_ciphertext(server, ciphertext, n, e):
	k = 0
	nbits = len(bin(n)[2:].strip('L'))

	for i in range(nbits):
		m = ((k + 1) * n) >> i
		printstr = to_printable(utils.integer_to_string(m))
		sys.stdout.write(printstr)
		sys.stdout.flush()
		ciphertext = double_plaintext(ciphertext, n, e)

		if server.parity_oracle(ciphertext) == True:
			k = 2 * k
		else:
			k = 2 * k + 1

		# Used for the "Hollywood" style printing
		sys.stdout.write("\b" * len(printstr))
		sys.stdout.write(" " * len(printstr))
		sys.stdout.write("\b" * len(printstr))
		sys.stdout.flush()

	m = ((k + 1) * n) >> nbits
	return utils.integer_to_string(m)

server = Server()
ciphertext = server.get_ciphertext()
n, e = server.get_public_key()

message = crack_ciphertext(server, ciphertext, n, e)
print message
