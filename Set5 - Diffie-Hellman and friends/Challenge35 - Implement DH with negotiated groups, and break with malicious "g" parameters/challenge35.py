import hashlib
import os
import crypto_utils as utils

# Honestly, I don't get that challenge.
# In order for the attack to work, you can't just modify the value of g,
# but you must also modify the value of A, otherwise agent_B receives a
# secret of A^b (mod p) which cannot be known by agent_M.
# But in that case the whole point of the challenge is lost, since we need
# to modify more things than just the group parameter g...
# A plain old MITM attack would have been just as effective, and make more sense.

class Agent(object):
	def gen_DH_params(self):
		x, X = utils.gen_DH_pair(self.p, self.g)
		self.x = x
		self.X = X

	def gen_secret(self, Y):
		self.secret = utils.gen_secret(self.x, Y, self.p)
	
	def send_group_params(self, p, g):
		self.p = p
		self.g = g
		return self.p, self.g

	def recv_group_params(self, p, g):
		self.p = p
		self.g = g

	def send_ACK(self):
		return "ACK"

	def recv_ACK(self, ack):
		return

	def send_pubX(self):
		self.gen_DH_params()
		return self.X

	def recv_pubX(self, Y):
		self.Y = Y
	
	def send_msg(self, msg):
		self.gen_secret(self.Y)
		iv = os.urandom(utils.BLOCK_SIZE)
		cipher = utils.AES_CBC_encrypt(msg, self.secret, iv)
		return cipher + iv

	def recv_msg(self, data):
		self.gen_secret(self.Y)
		cipher = data[:len(data) - utils.BLOCK_SIZE]
		iv = data[len(data) - utils.BLOCK_SIZE:]
		msg = utils.AES_CBC_decrypt(cipher, self.secret, iv)
		return msg

class MITM(object):
	def get_secret_from_int(self, s):
		s = hex(s)[2:].strip("L")

		if len(s) % 2 != 0:
			s = "0" + s

		s = s.decode('hex')
		sha1 = hashlib.sha1()
		sha1.update(s)
		secret = sha1.digest()[:utils.BLOCK_SIZE]
		return secret

	def send_group_params_1(self):
		return self.p, 1

	def send_group_params_p(self):
		return self.p, self.p

	def send_group_params_p_minus_1(self):
		return self.p, self.p - 1

	def recv_group_params(self, p, g):
		self.p = p
		self.g = g

	def send_ACK(self):
		return "ACK"

	def recv_ACK(self, ack):
		return

	def send_pubX(self, g, who):
		if who == "A":
			return self.B
		elif who == "B":
			if g == 1:
				return 1
			elif g == p:
				return 0
			else:
				return 1

	def recv_pubX(self, X, who):
		if who == "B":
			self.B = X

	def intercept_msg_1(self, data, who):
		secret = self.get_secret_from_int(1)
		cipher = data[:len(data) - utils.BLOCK_SIZE]
		iv = data[len(data) - utils.BLOCK_SIZE:]
		msg = utils.AES_CBC_decrypt(cipher, secret, iv)
		print "Mallory intercepted message: " + msg
		return data

	def intercept_msg_p(self, data, who):
		secret = self.get_secret_from_int(0)
		cipher = data[:len(data) - utils.BLOCK_SIZE]
		iv = data[len(data) - utils.BLOCK_SIZE:]
		msg = utils.AES_CBC_decrypt(cipher, secret, iv)
		print "Mallory intercepted message: " + msg
		return data

	def intercept_msg_p_minus_1(self, data, who):
		cipher = data[:len(data) - utils.BLOCK_SIZE]
		iv = data[len(data) - utils.BLOCK_SIZE:]

		if self.B == 1 or who == "B":
			secret = self.get_secret_from_int(1)
			msg = utils.AES_CBC_decrypt(cipher, secret, iv)
			print "Mallory intercepted message: " + msg

			# Reencrypt with A's key if A's key is p - 1
			try:
				if who == "B" and secret != self.secret_A:
					cipher = utils.AES_CBC_encrypt(msg, self.secret_A, iv)
					data = cipher + iv
			except:
				pass

			return data

		# Message sent from A, with B = -1. In that case A's secret could be 1 or p - 1.
		secret1 = self.get_secret_from_int(1)
		secret2 = self.get_secret_from_int(self.p - 1)

		# Use padding to determine if A encrypted with 1 or p - 1
		if utils.check_padding(cipher, secret1, iv) == True:
			self.secret_A = secret1
			msg = utils.AES_CBC_decrypt(cipher, secret1, iv)
			print "Mallory intercepted message: " + msg
			return data
		else:
			self.secret_A = secret2
			msg = utils.AES_CBC_decrypt(cipher, secret2, iv)
			print "Mallory intercepted message: " + msg

			# B's key is always 1. Reencrypt message with that key (here A had used p - 1)
			cipher = utils.AES_CBC_encrypt(msg, secret1, iv)
			return cipher + iv

message = "This is a message test 12345 $3cr3T!!!"
p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2

agent_A = Agent()
agent_B = Agent()
agent_M = MITM()

p, g = agent_A.send_group_params(p, g)
agent_M.recv_group_params(p, g)
p, g = agent_M.send_group_params_1()
agent_B.recv_group_params(p, g)

ack = agent_B.send_ACK()
agent_M.recv_ACK(ack)
ack = agent_M.send_ACK()
agent_A.recv_ACK(ack)

A = agent_A.send_pubX()
agent_M.recv_pubX(A, "A")
A = agent_M.send_pubX(1, "B")
agent_B.recv_pubX(A)

B = agent_B.send_pubX()
agent_M.recv_pubX(B, "B")
B = agent_M.send_pubX(1, "A")
agent_A.recv_pubX(B)

cipherA = agent_A.send_msg(message)
cipherA = agent_M.intercept_msg_1(cipherA, "A")
msgB = agent_B.recv_msg(cipherA)

cipherB = agent_B.send_msg(msgB)
cipherB = agent_M.intercept_msg_1(cipherB, "B")
msgA = agent_A.recv_msg(cipherB)

if msgA != message:
	print "Diffie-Hellman handshake failed."
else:
	print "Successfully established Diffie-Hellman handshake."

p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2

agent_A = Agent()
agent_B = Agent()
agent_M = MITM()

p, g = agent_A.send_group_params(p, g)
agent_M.recv_group_params(p, g)
p, g = agent_M.send_group_params_p()
agent_B.recv_group_params(p, g)

ack = agent_B.send_ACK()
agent_M.recv_ACK(ack)
ack = agent_M.send_ACK()
agent_A.recv_ACK(ack)

A = agent_A.send_pubX()
agent_M.recv_pubX(A, "A")
A = agent_M.send_pubX(p, "B")
agent_B.recv_pubX(A)

B = agent_B.send_pubX()
agent_M.recv_pubX(B, "B")
B = agent_M.send_pubX(p, "A")
agent_A.recv_pubX(B)

cipherA = agent_A.send_msg(message)
cipherA = agent_M.intercept_msg_p(cipherA, "A")
msgB = agent_B.recv_msg(cipherA)

cipherB = agent_B.send_msg(msgB)
cipherB = agent_M.intercept_msg_p(cipherB, "B")
msgA = agent_A.recv_msg(cipherB)

if msgA != message:
	print "Diffie-Hellman handshake failed."
else:
	print "Successfully established Diffie-Hellman handshake."

p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2

agent_A = Agent()
agent_B = Agent()
agent_M = MITM()

p, g = agent_A.send_group_params(p, g)
agent_M.recv_group_params(p, g)
p, g = agent_M.send_group_params_p_minus_1()
agent_B.recv_group_params(p, g)

ack = agent_B.send_ACK()
agent_M.recv_ACK(ack)
ack = agent_M.send_ACK()
agent_A.recv_ACK(ack)

A = agent_A.send_pubX()
agent_M.recv_pubX(A, "A")
A = agent_M.send_pubX(p - 1, "B")
agent_B.recv_pubX(A)

B = agent_B.send_pubX()
agent_M.recv_pubX(B, "B")
B = agent_M.send_pubX(p - 1, "A")
agent_A.recv_pubX(B)

cipherA = agent_A.send_msg(message)
cipherA = agent_M.intercept_msg_p_minus_1(cipherA, "A")
msgB = agent_B.recv_msg(cipherA)

cipherB = agent_B.send_msg(msgB)
cipherB = agent_M.intercept_msg_p_minus_1(cipherB, "B")
msgA = agent_A.recv_msg(cipherB)

if msgA != message:
	print "Diffie-Hellman handshake failed."
else:
	print "Successfully established Diffie-Hellman handshake."
