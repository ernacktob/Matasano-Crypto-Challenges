import os
import math
import hashlib

def randint(n):
	nbytes = int(math.floor(math.log(n) / math.log(256))) + 1
	randbytes = os.urandom(nbytes)
	randnum = int(randbytes.encode('hex'), 16)
	return randnum % n

def gen_DH_pair(p, g):
	x = randint(p)
	y = pow(g, x, p)
	return x, y

def gen_secret(x, Y, p):
	s = pow(Y, x, p)
	s1 = hex(s)[2:].strip('L')

	if len(s1) % 2 != 0:
		s1 = "0" + s1

	s_hex = s1.decode('hex')
	sha1 = hashlib.sha1()

	sha1.update(s_hex)
	secret = sha1.digest()
	return secret

p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2

a, A = gen_DH_pair(p, g)
b, B = gen_DH_pair(p, g)

secret_a = gen_secret(a, B, p)
secret_b = gen_secret(b, A, p)

print "secret_a = " + secret_a.encode('hex')
print "secret_b = " + secret_b.encode('hex')
