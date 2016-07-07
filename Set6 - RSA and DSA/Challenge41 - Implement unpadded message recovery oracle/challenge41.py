import base64
import random
import socket
import time

import crypto_utils as utils

def recvline(s):
	line = ""

	while True:
		data = s.recv(1)

		if len(data) == 0:
			break

		if data == '\n':
			return line

		line += data

	return line

class RSA_Client(object):
	def __init__(self, addr):
		self.addr = addr

	def connect_to_server(self):
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
		sock.connect(self.addr)
		self.sock = sock

		recvline(sock)
		recvline(sock)
		recvline(sock)
		recvline(sock)
		recvline(sock)

	def fetch_pubkey(self):
		self.connect_to_server()

		self.sock.send("pubkey\n")
		line = recvline(self.sock)
		self.n = int(line)
		line = recvline(self.sock)
		self.e = int(line)
	
	def submit_ciphertext(self):
		message = "This is a secret message."
		timestamp = time.time()
		data = str(timestamp) + " " + message
		self.cipher = utils.RSA_encrypt(data, self.n, self.e)

		self.connect_to_server()
		self.sock.send("decrypt\n")
		self.sock.send(base64.b64encode(self.cipher) + "\n")

		line = recvline(self.sock)
		msg = base64.b64decode(line)

		if msg != data:
			raise Exception("Error during decryption")

	def intercept_ciphertext(self):
		return self.cipher

class RSA_Spy_Client(object):
	def __init__(self, addr, client):
		self.addr = addr
		self.client = client

	def connect_to_server(self):
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
		sock.connect(self.addr)
		self.sock = sock

		recvline(sock)
		recvline(sock)
		recvline(sock)
		recvline(sock)
		recvline(sock)

	def fetch_pubkey(self):
		self.connect_to_server()

		self.sock.send("pubkey\n")
		line = recvline(self.sock)
		self.n = int(line)
		line = recvline(self.sock)
		self.e = int(line)
	
	def submit_ciphertext(self, ciphertext):
		self.connect_to_server()

		self.sock.send("decrypt\n")
		self.sock.send(base64.b64encode(ciphertext) + "\n")

		line = recvline(self.sock)

		if len(line) == 0:
			return None

		message = base64.b64decode(line)
		return message

	def recover_plaintext(self):
		ciphertext = self.client.intercept_ciphertext()
		self.fetch_pubkey()

		message = self.submit_ciphertext(ciphertext)

		if message != None:
			print "Direct decryption worked... wtf?"
			return message

		c = utils.string_to_integer(ciphertext)
		s = random.randint(2, self.n - 1)
		new_c = (pow(s, self.e, self.n) * c) % self.n
		new_ciphertext = utils.integer_to_string(new_c)
		new_message = self.submit_ciphertext(new_ciphertext)
		new_p = utils.string_to_integer(new_message)

		p = (new_p * utils.invmod(s, self.n)) % self.n
		message = utils.integer_to_string(p)

		return message

random.seed()
rsa_client = RSA_Client(('localhost', 9000))
rsa_client.fetch_pubkey()
rsa_client.submit_ciphertext()

spy = RSA_Spy_Client(('localhost', 9000), rsa_client)
message = spy.recover_plaintext()

print message
