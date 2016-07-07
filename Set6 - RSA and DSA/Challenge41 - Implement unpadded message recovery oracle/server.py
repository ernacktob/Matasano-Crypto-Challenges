import base64
import hashlib
import os
import select
import signal
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

def sigint_handler(signum, frame):
	global STOP
	STOP = True

def SHA256_HASH(data):
	hasher = hashlib.sha256()
	hasher.update(data)
	return hasher.digest()

class RSA_Server(object):
	def __init__(self, addr, e=3, l=4096):
		server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
		server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		server_sock.bind(addr)
		server_sock.listen(1)
		self.server_sock = server_sock

		n, d = utils.gen_private_key(l, e)
		self.e = e
		self.n = n
		self.d = d

		self.message_cache = set({})
		self.RUNNING = True

	def run(self):
		client_sock = None
		print "Server is up and running..."

		while self.RUNNING == True:
			try:
				client_sock, client_addr = self.server_sock.accept()
			except:
				break

			try:
				self.process_request(client_sock)
			except:
				pass

			client_sock.close()

		if client_sock != None:
			client_sock.close()
	
	def stop(self):
		self.RUNNING = False

	def close(self):
		self.server_sock.close()

	def process_request(self, sock):
		sock.send("Welcome to our RSA server.\n")
		sock.send("Commands:\n")
		sock.send("- pubkey:\tReceive our public key.\n")
		sock.send("- decrypt:\tDecrypt provided ciphertext.\n")
		sock.send("\n")

		line = recvline(sock)

		if line == "pubkey":
			self.provide_pubkey(sock)
		elif line == "decrypt":
			self.decrypt_ciphertext(sock)

	def provide_pubkey(self, sock):
		sock.send(str(self.n) + "\n" + str(self.e) + "\n")

	def decrypt_ciphertext(self, sock):
		line = recvline(sock)

		try:
			cipher = base64.b64decode(line)
		except:
			raise Exception("Invalid request")

		cipher_hash = SHA256_HASH(cipher)

		if cipher_hash in self.message_cache:
			raise Exception("Invalid request")

		message = utils.RSA_decrypt(cipher, self.n, self.d)
		sock.send(base64.b64encode(message) + "\n")
		self.message_cache.add(cipher_hash)

signal.signal(signal.SIGINT, sigint_handler)
rsa_server = RSA_Server(('localhost', 9000))
rsa_server.run()
rsa_server.close()
