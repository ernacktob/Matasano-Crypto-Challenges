import hashlib
import random

import crypto_utils as utils
import dsa

def SHA1_HASH(data):
	sha1 = hashlib.sha1()
	sha1.update(data)
	return sha1.digest()

def gen_fake_DSA_signature(g, p, q, y):
	if g == 0:
		return 0, random.randint(0, q - 1)

	if g == p + 1:
		z = random.randint(0, q - 1)
		r = pow(y, z, p) % q
		s = (r * utils.invmod(z, q)) % q
		return r, s

	return None

# DSA domain parameters
p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291

status, x, y = dsa.DSA_gen_per_user_keys(p, q, g)

if status != True:
	print "Could not generate per user keys."
	quit()

# This one doesn't really work because the verification is supposed to check that r and s are nonzero.
g = 0
r, s = gen_fake_DSA_signature(g, p, q, y)

if dsa.DSA_verify_signature(p, q, g, y, "Hello, world", r, s, SHA1_HASH, hashlib.sha1().block_size) == True:
	print "Sucessfully forged DSA signature for g = 0, message = \"Hello, world\""
else:
	print "Failed to forge DSA signature for g = 0, message = \"Hello, world\""

if dsa.DSA_verify_signature(p, q, g, y, "Goodbye, world", r, s, SHA1_HASH, hashlib.sha1().block_size) == True:
	print "Sucessfully forged DSA signature for g = 0, message = \"Goodbye, world\""
else:
	print "Failed to forge DSA signature for g = 0, message = \"Goodbye, world\""


g = p + 1
r, s = gen_fake_DSA_signature(g, p, q, y)

if dsa.DSA_verify_signature(p, q, g, y, "Hello, world", r, s, SHA1_HASH, hashlib.sha1().block_size) == True:
	print "Sucessfully forged DSA signature for g = p + 1, message = \"Hello, world\""
else:
	print "Failed to forge DSA signature for g = p + 1, message = \"Hello, world\""

if dsa.DSA_verify_signature(p, q, g, y, "Goodbye, world", r, s, SHA1_HASH, hashlib.sha1().block_size) == True:
	print "Sucessfully forged DSA signature for g = p + 1, message = \"Goodbye, world\""
else:
	print "Failed to forge DSA signature for g = p + 1, message = \"Goodbye, world\""
