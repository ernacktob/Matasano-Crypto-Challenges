import math
import os

import crypto_utils as utils

# Implementation of DSA based on
# http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf

def is_prime(p):
	return utils.is_probable_prime(p)

def gen_DSA_primes(L, N, seedlen, Hash, outlen):
	acceptable_pairs = [(1024, 160), (2048, 224), (2048, 256), (3072, 256)]

	if (L, N) not in acceptable_pairs:
		return False, None, None

	if seedlen < N:
		return False, None, None

	n = int(math.ceil(float(L) / float(outlen)) - 1)
	b = L - 1 - n * outlen

	while True:
		domain_parameter_seed = utils.string_to_integer(os.urandom(seedlen / 8))
		U = utils.string_to_integer(Hash(utils.integer_to_string(domain_parameter_seed))) % 2 ** (N - 1)
		q = 2 ** (N - 1) + U + 1 - (U % 2)
	
		if not is_prime(q):
			continue

		offset = 1
	
		for counter in range(4 * L):
			V = {}
	
			for j in range(n + 1):
				V[j] = utils.string_to_integer(Hash(utils.integer_to_string((domain_parameter_seed + offset + j) % 2 ** seedlen)))
	
			W = sum([V[j] * 2 ** (j * outlen) for j in range(n - 1)]) + (V[n] % 2 ** b) * 2 ** (n * outlen)
			X = W + 2 ** (L - 1)
			c = X % (2 * q)
			p = X - (c - 1)
	
			if p < 2 ** (L - 1):
				offset = offset + n + 1
				continue
	
			if is_prime(p):
				return True, p, q

			offset = offset + n + 1

	return False, None, None

def gen_DSA_generator(p, q):
	e = (p - 1) / q
	h = 2

	while h < p - 1:
		g = pow(h, e, p)

		if g != 1:
			return g

		h += 1

	return None

def DSA_gen_domain_params(L, N, seedlen, Hash, outlen):
	status, p, q = gen_DSA_primes(L, N, seedlen, Hash, outlen)

	if status == False:
		return False, None, None, None

	g = gen_DSA_generator(p, q)

	return True, p, q, g

def DSA_gen_per_user_keys(p, q, g):
	acceptable_pairs = [(1024, 160), (2048, 224), (2048, 256), (3072, 256)]

	N = len(bin(q)[2:])
	L = len(bin(p)[2:])

	if (L, N) not in acceptable_pairs:
		return False, None, None

	c = utils.string_to_integer(os.urandom((N + 64) / 8))
	x = c % (q - 1) + 1
	y = pow(g, x, p)

	return True, x, y

def gen_DSA_per_message_secret(p, q, g):
	acceptable_pairs = [(1024, 160), (2048, 224), (2048, 256), (3072, 256)]

	N = len(bin(q)[2:])
	L = len(bin(p)[2:])

	if (L, N) not in acceptable_pairs:
		return False, None, None

	c = utils.string_to_integer(os.urandom((N + 64) / 8))
	k = c % (q - 1) + 1

	k_inv = utils.invmod(k, q)
	return True, k, k_inv

def DSA_gen_signature(p, q, g, x, M, Hash, outlen):
	N = len(bin(q)[2:])

	while True:
		status, k, k_inv = gen_DSA_per_message_secret(p, q, g)
		
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

def DSA_verify_signature(p, q, g, y, M, r, s, Hash, outlen):
	N = len(bin(q)[2:])

	if r <= 0 or r >= q or s <= 0 or s >= q:
		return False

	w = utils.invmod(s, q)
	z = utils.string_to_integer(Hash(M)[: min(N, outlen) / 8])
	u1 = (z * w) % q
	u2 = (r * w) % q
	v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q

	if v == r:
		return True

	return False
