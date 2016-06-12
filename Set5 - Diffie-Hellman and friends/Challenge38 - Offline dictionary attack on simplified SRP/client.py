import hashlib
import socket

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

def SHA256_HASH(data):
	sha256 = hashlib.sha256()
	sha256.update(data)
	return sha256.digest()

class Simplified_SRP_Client(object):
	def __init__(self, sock, N, g, I, P):
		self.sock = sock
		self.N = N
		self.g = g
		self.I = I
		self.P = P

	def send_client_params(self):
		self.a = utils.randint(self.N)
		self.A = pow(self.g, self.a, self.N)
		self.sock.send(self.I + " " + str(self.A) + "\n")

	def recv_server_params(self):
		line = recvline(self.sock)
		self.salt = int(line.split(' ')[0])
		self.B = int(line.split(' ')[1])
		self.u = int(line.split(' ')[2])

	def gen_secret(self):
		x = int(SHA256_HASH(str(self.salt) + self.P).encode('hex'), 16)
		S = pow(self.B, self.a + self.u * x, self.N)
		self.K = SHA256_HASH(str(S))

	def send_hmac(self):
		hmac = utils.HMAC(str(self.salt), self.K, SHA256_HASH, hashlib.sha256().block_size)
		self.sock.send(hmac.encode('hex') + "\n")

N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2
I = "test@gmail.com"
P = 'anaconda'

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
s.connect(('localhost', 9000))

C = Simplified_SRP_Client(s, N, g, I, P)
C.send_client_params()
C.recv_server_params()
C.gen_secret()
C.send_hmac()

print recvline(s)
