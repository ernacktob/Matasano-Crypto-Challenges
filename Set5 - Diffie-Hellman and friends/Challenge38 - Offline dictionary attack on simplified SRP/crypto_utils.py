import hashlib
import math
import os
from Crypto.Cipher import AES

BLOCK_SIZE = 16

def PKCS7_Pad(m):
	return m + chr(BLOCK_SIZE - len(m) % BLOCK_SIZE) * (BLOCK_SIZE - len(m) % BLOCK_SIZE)

def PKCS7_Unpad(m):
	return m.strip(m[-1])

def XOR_blocks(b1, b2):
	return "".join([chr(ord(b1[i]) ^ ord(b2[i])) for i in range(len(b1))])

def AES_CBC_encrypt(m, k, iv):
	m = PKCS7_Pad(m)
	cblock = [x for x in iv]
	c = ""

	cipher = AES.new(k)

	for i in range(len(m) / BLOCK_SIZE):
		p1 = XOR_blocks(cblock, m[i * BLOCK_SIZE: (i + 1) * BLOCK_SIZE])
		c1 = cipher.encrypt(p1)
		cblock = [x for x in c1]
		c += c1

	return c

def AES_CBC_decrypt(c, k, iv):
	m = ""
	cipher = AES.new(k)

	for i in range(len(c) / BLOCK_SIZE - 1, 0, -1):
		p1 = cipher.decrypt(c[i * BLOCK_SIZE: (i + 1) * BLOCK_SIZE])
		cblock = c[(i - 1) * BLOCK_SIZE: i * BLOCK_SIZE]
		m = XOR_blocks(cblock, p1) + m
	
	p1 = cipher.decrypt(c[:BLOCK_SIZE])
	m = XOR_blocks(iv, p1) + m
	return PKCS7_Unpad(m)

def check_padding(c, k, iv):
	m = ""
	cipher = AES.new(k)

	for i in range(len(c) / BLOCK_SIZE - 1, 0, -1):
		p1 = cipher.decrypt(c[i * BLOCK_SIZE: (i + 1) * BLOCK_SIZE])
		cblock = c[(i - 1) * BLOCK_SIZE: i * BLOCK_SIZE]
		m = XOR_blocks(cblock, p1) + m
	
	p1 = cipher.decrypt(c[:BLOCK_SIZE])
	m = XOR_blocks(iv, p1) + m

	if ord(m[-1]) >= 16:
		return False

	stripped = m.strip(m[-1])

	if len(m) - len(stripped) != ord(m[-1]):
		return False

	return True

def HMAC(message, key, hash_func, blocksize):
	if len(key) > blocksize:
		key = hash_func(key)
	if len(key) < blocksize:
		key = key + "\x00" * (blocksize - len(key))

	opad = "\x5c" * blocksize
	ipad = "\x36" * blocksize
	o_key_pad = "".join([chr(ord(opad[i]) ^ ord(key[i])) for i in range(blocksize)])
	i_key_pad = "".join([chr(ord(ipad[i]) ^ ord(key[i])) for i in range(blocksize)])

	return hash_func(o_key_pad + hash_func(i_key_pad + message))

def randint(n):
	nbytes = int(math.floor(math.log(n) / math.log(256))) + 1
	randbytes = os.urandom(nbytes)
	randnum = int(randbytes.encode('hex'), 16)
	return randnum % n

def gen_DH_pair(p, g):
	x = randint(p)
	X = pow(g, x, p)
	return x, X

def gen_secret(x, Y, p):
	s = pow(Y, x, p)
	s1 = hex(s)[2:].strip('L')

	if len(s1) % 2 != 0:
		s1 = "0" + s1

	s_hex = s1.decode('hex')
	sha1 = hashlib.sha1()

	sha1.update(s_hex)
	secret = sha1.digest()
	return secret[:BLOCK_SIZE]
