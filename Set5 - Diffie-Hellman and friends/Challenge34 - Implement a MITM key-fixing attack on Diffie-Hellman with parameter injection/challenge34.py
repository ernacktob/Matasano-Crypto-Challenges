import hashlib
import os
import crypto_utils as utils

class Agent(object):
	def gen_DH_params(self):
		x, X = utils.gen_DH_pair(self.p, self.g)
		self.x = x
		self.X = X

	def gen_secret(self, Y):
		self.secret = utils.gen_secret(self.x, Y, self.p)
	
	def send_public_data(self, p, g):
		self.p = p
		self.g = g
		self.gen_DH_params()
		return self.p, self.g, self.X

	def recv_public_data(self, p, g, Y):
		self.p = p
		self.g = g
		self.gen_DH_params()
		self.gen_secret(Y)

	def send_pubX(self):
		return self.X

	def recv_pubX(self, X):
		self.gen_secret(X)
	
	def send_msg(self, msg):
		iv = os.urandom(utils.BLOCK_SIZE)
		cipher = utils.AES_CBC_encrypt(msg, self.secret, iv)
		return cipher + iv

	def recv_msg(self, data):
		cipher = data[:len(data) - utils.BLOCK_SIZE]
		iv = data[len(data) - utils.BLOCK_SIZE:]
		msg = utils.AES_CBC_decrypt(cipher, self.secret, iv)
		return msg

class MITM(object):
	def send_public_data(self):
		return self.p, self.g, self.p

	def recv_public_data(self, p, g, A):
		self.p = p
		self.g = g

	def send_pubX(self):
		return self.p

	def recv_pubX(self, B):
		return

	def intercept_msg(self, data):
		sha1 = hashlib.sha1()
		sha1.update("\x00")
		secret = sha1.digest()[:utils.BLOCK_SIZE]

		cipher = data[:len(data) - utils.BLOCK_SIZE]
		iv = data[len(data) - utils.BLOCK_SIZE:]
		msg = utils.AES_CBC_decrypt(cipher, secret, iv)
		print "Mallory intercepted message: " + msg
		return data

message = "This is a message test 12345 $3cr3T!!!"
p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2

agent_A = Agent()
agent_B = Agent()
agent_M = MITM()

p, g, A = agent_A.send_public_data(p, g)
agent_M.recv_public_data(p, g, A)
p, g, A = agent_M.send_public_data()
agent_B.recv_public_data(p, g, A)

B = agent_B.send_pubX()
agent_M.recv_pubX(B)
B = agent_M.send_pubX()
agent_A.recv_pubX(B)

cipherA = agent_A.send_msg(message)
cipherA = agent_M.intercept_msg(cipherA)
msgB = agent_B.recv_msg(cipherA)

cipherB = agent_B.send_msg(msgB)
cipherB = agent_M.intercept_msg(cipherB)
msgA = agent_A.recv_msg(cipherB)

if msgA != message:
	print "Diffie-Hellman handshake failed."
else:
	print "Successfully established Diffie-Hellman handshake."
