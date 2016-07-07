import hashlib
import random

import crypto_utils as utils
import dsa

def SHA1_HASH(data):
	sha1 = hashlib.sha1()
	sha1.update(data)
	return sha1.digest()

def parse_signatures(data):
	lines = data.split('\n')
	signatures = []
	sig = {}

	for line in lines:
		if line.startswith('msg: '):
			sig['msg'] = ' '.join(line.split(' ')[1:])
		elif line.startswith('s: '):
			sig['s'] = int(line.split(' ')[1])
		elif line.startswith('r: '):
			sig['r'] = int(line.split(' ')[1])
		elif line.startswith('m: '):
			sig['m'] = int(line.split(' ')[1], 16)
			signatures.append(sig)
			sig = {}
	
	return signatures

def find_signatures_with_same_k(signatures):
	sigs = {}

	# r = (g^k mod p) mod q, so same k --> same r.
	for sig in signatures:
		if sig['r'] not in sigs:
			sigs[sig['r']] = []

		sigs[sig['r']].append(sig)
	
	for r in sigs:
		if len(sigs[r]) > 1:
			return sigs[r]

	return None

def find_k_from_repeated_sigs(q, sigs):
	m1 = sigs[0]['m']
	m2 = sigs[1]['m']
	s1 = sigs[0]['s']
	s2 = sigs[1]['s']

	k = ((m1 - m2) * utils.invmod(s1 - s2, q)) % q
	return k

def recover_x_from_k(q, k, r, s, msg, Hash, outlen):
	N = len(bin(q)[2:])
	x = (((s * k) - utils.string_to_integer(Hash(msg)[: min(N, outlen) / 8])) * utils.invmod(r, q)) % q

	return x

# DSA domain parameters
p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291

# DSA public key
y = 0x2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821

f = open('44.txt', 'r')
data = f.read()
f.close()

signatures = parse_signatures(data)
repeated_sigs = find_signatures_with_same_k(signatures)
k = find_k_from_repeated_sigs(q, repeated_sigs)
r = repeated_sigs[0]['r']
s = repeated_sigs[0]['s']
msg = repeated_sigs[0]['msg']
x = recover_x_from_k(q, k, r, s, msg, SHA1_HASH, hashlib.sha1().block_size * 8)

if SHA1_HASH(utils.integer_to_string(x).encode('hex')).encode('hex') == "ca8f6f7c66fa362d40760d135b763eb8527d3d52":
	print "Found private key x = " + utils.integer_to_string(x).encode('hex')
else:
	print "Failed to find private key."
