import hashlib
import os
import select
import signal
import socket

import crypto_utils as utils

STOP = False

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

class SRP_Server(object):
	def __init__(self, sock, N, g, k, I, P):
		self.sock = sock
		self.N = N
		self.g = g
		self.k = k
		self.I = I

		self.salt = utils.randint(2 ** 256)
		xH = SHA256_HASH(str(self.salt) + P).encode('hex')
		x = int(xH, 16)
		self.v = pow(self.g, x, self.N)

	def recv_client_params(self):
		line = recvline(self.sock)

		if line.count(' ') != 1:
			raise Exception("Invalid request")

		I = line.split(' ')[0]
		A = line.split(' ')[1]

		if I != self.I:
			raise Exception("Invalid request")

		try:
			A = int(A)
		except:
			raise Exception("Invalid request")

		self.A = A

	def send_server_params(self):
		self.b = utils.randint(self.N)
		self.B = self.k * self.v + pow(self.g, self.b, self.N)
		self.sock.send(str(self.salt) + " " + str(self.B) + "\n")

	def gen_secret(self):
		uH = SHA256_HASH(str(self.A) + str(self.B)).encode('hex')
		u = int(uH, 16)
		S = pow(self.A * pow(self.v, u, self.N), self.b, self.N)
		self.K = SHA256_HASH(str(S))

	def validate_hmac(self):
		line = recvline(self.sock)

		try:
			hmac = line.decode('hex')
		except:
			raise Exception("Invalid request")

		hmac2 = utils.HMAC(str(self.salt), self.K, SHA256_HASH, hashlib.sha256().block_size)

		if hmac == hmac2:
			self.sock.send("OK\n")
		else:
			self.sock.send("INVALID\n")

N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2
k = 3
I = "test@gmail.com"
P = "passw0rd"

server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_sock.bind(('localhost', 9000))
server_sock.listen(1)

signal.signal(signal.SIGINT, sigint_handler)
client_sock = None

while STOP == False:
	try:
		client_sock, client_addr = server_sock.accept()
	except:
		break

	try:
		S = SRP_Server(client_sock, N, g, k, I, P)
		S.recv_client_params()
		S.send_server_params()
		S.gen_secret()
		S.validate_hmac()
	except:
		pass

	client_sock.close()

if client_sock != None:
	client_sock.close()

server_sock.close()
