import random

import crypto_utils as utils

def gen_padding_string(n):
	return "".join([chr(random.randint(1, 255)) for i in range(n)])

def PKCS1_v1_5_Pad(D, k):
	PS = gen_padding_string(k - 3 - len(D))
	EB = "\x00\x02" + PS + "\x00" + D
	return EB

def PKCS1_v1_5_Unpad(EB):
	for i in range(2, len(EB)):
		if EB[i] == "\x00":
			break
	
	return "".join(EB[i + 1:])

class Server(object):
	def __init__(self):
		self.e = 65537
		self.n, self.d = utils.gen_private_key(256, self.e)
		message = PKCS1_v1_5_Pad("kick it, CC", 256 / 8)
		self.ciphertext = utils.RSA_encrypt(message, self.n, self.e)
	
	def get_ciphertext(self):
		return self.ciphertext

	def get_public_key(self):
		return self.n, self.e

	def padding_oracle(self, cipher):
		msg = utils.RSA_decrypt(cipher, self.n, self.d)

		if msg[0] == "\x00" and msg[1] == "\x02":
			return True

		return False

def Bleichenbacher_attack(server, ciphertext, n, e):
	k = (len(bin(n)[2:].strip('L')) + 7) / 8
	B = 2 ** (8 * (k - 2))
	c = utils.string_to_integer(ciphertext)

	# Step 1 (skip blinding)
	si = 1
	c0 = c
	Mi = [[2 * B, 3 * B - 1]]
	i = 1

	while True:
		si_1 = si
		Mi_1 = Mi

		# Step 2
		if i == 1:
			# Step 2.a
			si = (n + 3 * B - 1) / (3 * B)	# ceil(n / (3B))

			while server.padding_oracle(utils.integer_to_string((c0 * pow(si, e, n)) % n)) != True:
				si += 1
		elif len(Mi) >= 2:
			print "Step 2.b not yet implemented"
			quit()
		else:
			# Step 2.c
			a = Mi[0][0]
			b = Mi[0][1]

			ri = (2 * b * si_1 - 2 * B + n - 1) / n	# ceil((2 * b * si_1 - 2 * B) / n)
			conforming = False

			while not conforming:
				for si in range((2 * B + ri * n + b - 1) / b, (3 * B - 1 + ri * n) / a + 1):
					if server.padding_oracle(utils.integer_to_string((c0 * pow(si, e, n)) % n)) == True:
						conforming = True
						break
				else:
					ri += 1

		# Step 3
		Mi = []

		for Ir in Mi_1:
			a = Ir[0]
			b = Ir[1]

			for r in range((a * si - 3 * B + 1 + n - 1) / n, (b * si - 2 * B) / n + 1):
				new_a = max(a, (2 * B + r * n + si - 1) / si)	# to get the ceiling
				new_b = min(b, (3 * B - 1 + r * n) / si)

				if new_b >= new_a:
					Mi.append([new_a, new_b])

		# Step 4
		if len(Mi) == 1 and Mi[0][0] == Mi[0][1]:
			m = Mi[0][0]
			break

		i += 1
	
	return PKCS1_v1_5_Unpad(utils.integer_to_string(m, k))

server = Server()
ciphertext = server.get_ciphertext()
n, e = server.get_public_key()

message = Bleichenbacher_attack(server, ciphertext, n, e)
print message
