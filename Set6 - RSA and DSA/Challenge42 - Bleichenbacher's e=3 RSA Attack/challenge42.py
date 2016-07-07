import decimal
import hashlib
import re

import crypto_utils as utils

def SHA256_HASH(data):
	hasher = hashlib.sha256()
	hasher.update(data)
	return hasher.digest()

# See https://tools.ietf.org/html/rfc3447#section-9.2
def EMSA_PKCS1_v1_5_ENCODE(M, emLen):
	H = SHA256_HASH(M)
	ASN1_GOOP = "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"
	T = ASN1_GOOP + H
	tLen = len(T)

	if emLen < tLen + 11:
		raise Exception("intended encoded message length too short")

	PS = (emLen - tLen - 3) * "\xff"
	EM = "\x00\x01" + PS + "\x00" + T
	return EM

# See https://tools.ietf.org/html/rfc3447#section-8.2.1
def RSASSA_PKCS1_v1_5_SIGN(n, d, M):
	k = (len(bin(n)[2:]) + 7) / 8	# Length of n in octets
	
	try:
		EM = EMSA_PKCS1_v1_5_ENCODE(M, k)
	except:
		raise Exception("RSA modulus too short")

	m = utils.string_to_integer(EM)
	s = utils.RSA_decrypt(m, n, d)
	S = utils.integer_to_string(s)
	return S

# See https://tools.ietf.org/html/rfc3447#section-8.2.2
def RSASSA_PKCS1_v1_5_VERIFY(n, e, M, S):
	k = (len(bin(n)[2:]) + 7) / 8	# Length of n in octets

	if len(S) != k:
		return False

	s = utils.string_to_integer(S)
	m = pow(s, e, n)

	try:
		EM_ = utils.integer_to_string(m, k)
	except:
		return False

	try:
		EM = EMSA_PKCS1_v1_5_ENCODE(M, k)
	except:
		raise Exception("RSA modulus too short")

	if EM == EM_:
		return True

	return False

# This method doesn't properly check the padding
# and is vulnerable to Bleichenbacher's attack.
def check_signature_weak(n, e, M, S):
	k = (len(bin(n)[2:]) + 7) / 8	# Length of n in octets

	if len(S) != k:
		return False

	s = utils.string_to_integer(S)
	m = pow(s, e, n)

	try:
		EM = utils.integer_to_string(m, k)
	except:
		return False

	H = SHA256_HASH(M)
	ASN1_GOOP = "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"
	T = ASN1_GOOP + H

	if re.match("\x00\x01" + "[\xff]+" + "\x00" + re.escape(T), EM):
		return True

	return False

def get_public_key():
	e = 3
	n, d = utils.gen_private_key(2048, e)	# 1024 bits is too short. ASN1_GOOP and HASH take too much space, no room to find perfect cube...
	return n, e

def cube_root(x):
	decimal.getcontext().prec = 2 * len(str(x))
	power = decimal.Decimal(1) / decimal.Decimal(3)
	x = decimal.Decimal(str(x))
	root = x ** power

	integer_root = root.quantize(decimal.Decimal('1.'), rounding=decimal.ROUND_DOWN)
	return int(integer_root)

def forge_signature(data, n, e):
	k = (len(bin(n)[2:]) + 7) / 8
	b = 8 * k

	H = SHA256_HASH(data)
	ASN1_GOOP = "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"
	D = utils.string_to_integer(ASN1_GOOP + H)

	N = 2 ** 416 - D	# 32 (HASH) + 19 (ASN1_GOOP) + 1 (\x00) = 52 ---> 416 bits
	X = b - 440		# N * 2^X < 2^(b - 15 - 8) (Need 8 bits padding "\xff" at least), and need multiple of 8.
	MAX_GARBAGE = 2 ** X - 1

	# By picking MAX_GARBAGE as high as possible, we are most likely to find a cube root
	# whose cube is within the range that starts with the desired bytes.
	MAX_S3 = 2 ** (b - 15) - N * 2 ** X + MAX_GARBAGE
	s = cube_root(MAX_S3)

	return utils.integer_to_string(s, k)

message = "hi mom"

n, e = get_public_key()
signature = forge_signature(message, n, e)

if check_signature_weak(n, e, message, signature) == True:
	print "Forged signature accepted by weak check function."
else:
	print "Forged signature refused by weak check function."

if RSASSA_PKCS1_v1_5_VERIFY(n, e, message, signature) == True:
	print "Wow, the forged signature also got accepted by RSASSA_PKCS1_v1_5_VERIFY."
else:
	print "RSASSA_PKCS1_v1_5_VERIFY did not accept the forged signature."
