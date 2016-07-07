import hashlib
import random

import crypto_utils as utils
import dsa

def gen_DSA_per_message_secret_weak(p, q, g):
	acceptable_pairs = [(1024, 160), (2048, 224), (2048, 256), (3072, 256)]

	N = len(bin(q)[2:])
	L = len(bin(p)[2:])

	if (L, N) not in acceptable_pairs:
		return False, None, None

	# Generate random k between 1 and 2^16 (weak!)
	k = random.randint(1, 2 ** 16)
	k_inv = utils.invmod(k, q)

	return True, k, k_inv

def DSA_gen_signature_weak(p, q, g, x, M, Hash, outlen, k=None):
	N = len(bin(q)[2:])

	# Force k to specific value to test signature generation from recovered secret key x.
	if k != None:
		k_inv = utils.invmod(k, q)
		r = pow(g, k, p) % q
		z = utils.string_to_integer(Hash(M)[: min(N, outlen) / 8])
		s = (k_inv * (z + x * r)) % q
		return True, r, s

	while True:
		status, k, k_inv = gen_DSA_per_message_secret_weak(p, q, g)
		
		if status == False:
			return False, None, None
	
		r = pow(g, k, p) % q
	
		if r == 0:
			continue

		z = utils.string_to_integer(Hash(M)[: min(N, outlen) / 8])	# Leftmost min(N, outlen) bits of Hash(M)
		s = (k_inv * (z + x * r)) % q

		if s == 0:
			continue

		break

	return True, r, s

def SHA1_HASH(data):
	sha1 = hashlib.sha1()
	sha1.update(data)
	return sha1.digest()

def recover_x_from_k(q, k, r, s, msg, Hash, outlen):
	N = len(bin(q)[2:])
	x = (((s * k) - utils.string_to_integer(Hash(msg)[: min(N, outlen) / 8])) * utils.invmod(r, q)) % q

	return x

def recover_private_key(p, q, g, r, s, msg, Hash, outlen):
	for k in range(1, 2 ** 16 + 1):
		# r is defined as (g^k mod p) mod q, so check that this is the case.
		if pow(g, k, p) % q == r:
			x = recover_x_from_k(q, k, r, s, msg, Hash, outlen)
			return x, k

	return None, None

def test_sample_signature():
	# DSA domain parameters
	p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
	q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
	g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291
	
	# DSA public key
	y = 0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17
	
	# Message
	msg = "For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n"

	# DSA Signature
	r = 548099063082341131477253921760299949438196259240
	s = 857042759984254168557880549501802188789837994940

	# Check that message hash is correct.
	if SHA1_HASH(msg).encode('hex') != "d2d0714f014a9784047eaeccf956520045c45265":
		print "Wrong SHA-1 hash for the sample message."
		return

	x, k = recover_private_key(p, q, g, r, s, msg, SHA1_HASH, hashlib.sha1().block_size * 8)

	if x == None:
		print "Failed to recover DSA private key for sample message."
		return

	# Check that this x, k pair produces the same signature.
	status, r1, s1 = DSA_gen_signature_weak(p, q, g, x, msg, SHA1_HASH, hashlib.sha1().block_size * 8, k)

	if status == False or r1 != r or s1 != s:
		print "Failed to recover DSA private key for sample message."
		return

	# Check agains SHA-1 hash provided.
	if SHA1_HASH(utils.integer_to_string(x).encode('hex')).encode('hex') != "0954edd5e0afe5542a4adf012611a91912a3ec16":
		print "Failed to recover DSA private key for sample message."
		return

	print "DSA private key for sample message: x = " + utils.integer_to_string(x).encode('hex')

def test_generated_signature():
	msg = "This is a test message."
	status, p, q, g = dsa.DSA_gen_domain_params(2048, 256, 2048, SHA1_HASH, hashlib.sha1().block_size * 8)

	if status == False:
		print "Failed to generate DSA domain parameters."
		return

	status, x, y = dsa.DSA_gen_per_user_keys(p, q, g)

	if status == False:
		print "Failed to generate DSA per-user keys."
		return

	status, r, s = dsa.DSA_gen_signature(p, q, g, x, msg, SHA1_HASH, hashlib.sha1().block_size * 8)

	if status == False:
		print "Failed to generate DSA signature."
		return

	if dsa.DSA_verify_signature(p, q, g, y, msg, r, s, SHA1_HASH, hashlib.sha1().block_size * 8) == False:
		print "Failed to verify DSA signature."
		return

	x1, k = recover_private_key(p, q, g, r, s, msg, SHA1_HASH, hashlib.sha1().block_size * 8)

	if x == None or x1 != x:
		print "Could not recover DSA private key for properly signed message."
		return

	print "Somehow successfully recovered DSA private key for properly signed message: x = " + utils.integer_to_string(x1).encode('hex')

def test_weak_signature():
	msg = "Talk to the hand."
	status, p, q, g = dsa.DSA_gen_domain_params(2048, 256, 2048, SHA1_HASH, hashlib.sha1().block_size * 8)

	if status == False:
		print "Failed to generate DSA domain parameters."
		return

	status, x, y = dsa.DSA_gen_per_user_keys(p, q, g)

	if status == False:
		print "Failed to generate DSA per-user keys."
		return

	status, r, s = DSA_gen_signature_weak(p, q, g, x, msg, SHA1_HASH, hashlib.sha1().block_size * 8)

	if status == False:
		print "Failed to generate weak DSA signature."
		return

	if dsa.DSA_verify_signature(p, q, g, y, msg, r, s, SHA1_HASH, hashlib.sha1().block_size * 8) == False:
		print "Failed to verify DSA signature."
		return

	x1, k = recover_private_key(p, q, g, r, s, msg, SHA1_HASH, hashlib.sha1().block_size * 8)

	if x == None or x1 != x:
		print "Could not recover DSA private key for weak signature."
		return

	print "Successfully recovered DSA private key for weak signature: x = " + utils.integer_to_string(x1).encode('hex')

random.seed()
test_sample_signature()
test_generated_signature()
test_weak_signature()
