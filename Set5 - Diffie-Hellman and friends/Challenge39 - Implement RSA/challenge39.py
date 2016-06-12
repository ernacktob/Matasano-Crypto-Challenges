import math
import random

def egcd(a, b):
	old_g = a
	old_x = 1
	old_y = 0
	g = b
	x = 0
	y = 1

	while g != 0:
		q = old_g / g

		temp = old_g
		old_g = g
		g = temp - q * g

		temp = old_x
		old_x = x
		x = temp - q * x

		temp = old_y
		old_y = y
		y = temp - q * y

	return old_g, old_x, old_y

def invmod(a, m):
	g, x, y = egcd(a, m)

	if g != 1:
		return None

	return x % m

def MillerRabin(n, k):
	d = n - 1
	r = 0

	while d % 2 == 0:
		r += 1
		d /= 2

	for i in range(k):
		a = random.randint(2, n - 2)
		x = pow(a, d, n)

		if x == 1 or x == n - 1:
			continue

		for j in range(r - 1):
			x = pow(x, 2, n)

			if x == 1:
				return False
			if x == n - 1:
				break
		else:
			return False

	return True

def is_probable_prime(n):
	small_primes = [3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97
			,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179
			,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269
			,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367
			,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461
			,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571
			,577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,661
			,673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773
			,787,797,809,811,821,823,827,829,839,853,857,859,863,877,881,883
			,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997]

	if n == 1:
		return False

	if n == 2:
		return True

	for p in small_primes:
		if n % p == 0:
			if n == p:
				return True

			return False

	return MillerRabin(n, 100)

def randprime_range(a, b):
	if a % 2 == 0:
		a = a + 1
	if b % 2 == 0:
		b = b - 1

	n = random.randrange(a, b, 2)

	while not is_probable_prime(n):
		n = random.randrange(a, b, 2)

	return n

def gen_private_key(l, e):
	# Generete p and q in so that they are around l / 2 bits and the product is l bits.
	p = randprime_range(2 ** (l / 2 - 1), 2 ** (l / 2) - 1)
	q = randprime_range((2 ** (l - 1) + p - 1) / p, (2 ** l - 1) / p)
	phi = (p - 1) * (q - 1)

	d = invmod(e, phi)

	while d == None:
		p = randprime_range(2 ** (l / 2 - 1), 2 ** (l / 2) - 1)
		q = randprime_range((2 ** (l - 1) + p - 1) / p, (2 ** l - 1) / p)
		phi = (p - 1) * (q - 1)

		d = invmod(e, phi)

	n = p * q
	return n, d

def RSA_encrypt(msg, n, e):
	m = int(msg.encode('hex'), 16)
	c = pow(m, e, n)
	
	xC = hex(c)[2:].strip('L')

	if len(xC) % 2 != 0:
		xC = '0' + xC
	
	cipher = xC.decode('hex')
	return cipher

def RSA_decrypt(cipher, n, d):
	c = int(cipher.encode('hex'), 16)
	m = pow(c, d, n)

	xM = hex(m)[2:].strip('L')

	if len(xM) % 2 != 0:
		xM = '0' + xM
	
	msg = xM.decode('hex')
	return msg

random.seed()
message = "This is a message!"
e = 3
n, d = gen_private_key(4096, e)

cipher = RSA_encrypt(message, n, e)
msg = RSA_decrypt(cipher, n, d)

print "Modulus length: " + str(len(bin(n)[2:]))

if msg == message:
	print "Successfully decrypted RSA message."
else:
	print "Error during RSA decryption."
