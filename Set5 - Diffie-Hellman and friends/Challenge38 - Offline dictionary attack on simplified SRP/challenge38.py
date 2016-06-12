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

class MITM_SRP_Server(object):
	def __init__(self, sock, N, g):
		self.sock = sock
		self.N = N
		self.g = g
		self.cracked_db = {}

		self.salt = 0	# For ease of computation

	def recv_client_params(self):
		line = recvline(self.sock)

		if line.count(' ') != 1:
			raise Exception("Invalid request")

		I = line.split(' ')[0]
		A = line.split(' ')[1]

		try:
			A = int(A)
		except:
			raise Exception("Invalid request")

		self.I = I
		self.A = A

	def send_server_params(self):
		self.b = 1	# For ease of computation of S (don't need to do exponentiation)
		self.B = pow(self.g, self.b, self.N)
		self.u = 1	# Also to avoid exponentiation
		self.sock.send(str(self.salt) + " " + str(self.B) + " " + str(self.u) + "\n")

	def recv_hmac(self):
		line = recvline(self.sock)

		try:
			hmac = line.decode('hex')
		except:
			raise Exception("Invalid request")

		self.hmac = hmac
		self.sock.send("INVALID\n") # Troll the client

	def crack_password(self):
		f = open('/usr/share/dict/words', 'r')
		words = f.read().split('\n')
		password = None

		for P in words:
			x = int(SHA256_HASH(str(0) + P).encode('hex'), 16)
			v = pow(self.g, x, self.N)
			S = (self.A * v) % self.N
			K = SHA256_HASH(str(S))
			hmac = utils.HMAC(str(0), K, SHA256_HASH, hashlib.sha256().block_size)

			if hmac == self.hmac:
				password = P
				break

		if password != None:
			self.cracked_db[self.I] = password
			print "Cracked password for %s: %s"%(self.I, password)

N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2

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
		S = MITM_SRP_Server(client_sock, N, g)
		S.recv_client_params()
		S.send_server_params()
		S.recv_hmac()
		S.crack_password()
	except:
		pass

	client_sock.close()

if client_sock != None:
	client_sock.close()

server_sock.close()
