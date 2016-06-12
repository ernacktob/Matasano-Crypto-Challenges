import hashlib
import os
import crypto_utils as utils

def SHA256_HASH(data):
	hasher = hashlib.sha256()
	hasher.update(data)
	return hasher.digest()

class SRP_Server(object):
	def __init__(self, N, g, k, I, P):
		self.N = N
		self.g = g
		self.k = k
		self.I = I

		self.salt = utils.randint(2 ** 256)
		xH = SHA256_HASH(str(self.salt) + P).encode('hex')
		x = int(xH, 16)
		self.v = pow(self.g, x, self.N)

	def recv_client_params(self, I, A):
		if I != self.I:
			print "Invalid email."
			quit()

		self.A = A

	def send_server_params(self):
		self.b = utils.randint(self.N)
		self.B = self.k * self.v + pow(self.g, self.b, self.N)

		return self.salt, self.B

	def gen_secret(self):
		uH = SHA256_HASH(str(self.A) + str(self.B)).encode('hex')
		u = int(uH, 16)
		S = pow(self.A * pow(self.v, u, self.N), self.b, self.N)
		self.K = SHA256_HASH(str(S))

	def validate_hmac(self, hmac):
		hmac2 = utils.HMAC(str(self.salt), self.K, SHA256_HASH, hashlib.sha256().block_size)

		if hmac == hmac2:
			return "OK"

		return None

class SRP_Client(object):
	def __init__(self, N, g, k, I, P):
		self.N = N
		self.g = g
		self.k = k
		self.I = I
		self.P = P
	
	def send_client_params(self):
		self.a = utils.randint(self.N)
		self.A = pow(self.g, self.a, self.N)

		return self.I, self.A

	def recv_server_params(self, salt, B):
		self.salt = salt
		self.B = B

	def gen_secret(self):
		uH = SHA256_HASH(str(self.A) + str(self.B)).encode('hex')
		u = int(uH, 16)
		xH = SHA256_HASH(str(self.salt) + self.P).encode('hex')
		x = int(xH, 16)
		S = pow(self.B - self.k * pow(self.g, x, self.N), self.a + u * x, self.N)
		self.K = SHA256_HASH(str(S))

	def send_HMAC(self):
		return utils.HMAC(str(self.salt), self.K, SHA256_HASH, hashlib.sha256().block_size)

N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2
k = 3
I = "test@gmail.com"
P = "passw0rd"

S = SRP_Server(N, g, k, I, P)
C = SRP_Client(N, g, k, I, P)

I, A = C.send_client_params()
S.recv_client_params(I, A)

salt, B = S.send_server_params()
C.recv_server_params(salt, B)

C.gen_secret()
S.gen_secret()

hmac = C.send_HMAC()
res = S.validate_hmac(hmac)

if res == "OK":
	print "SRP transaction successfully completed."
else:
	print "There was an error during the SRP transaction."
