import random
import decimal
import crypto_utils as utils

e = 3

def get_three_ciphertexts():
	message = "This is a message"

	n_0, d_0 = utils.gen_private_key(4096, e)
	n_1, d_1 = utils.gen_private_key(4096, e)
	n_2, d_2 = utils.gen_private_key(4096, e)

	cipher_0 = utils.RSA_encrypt(message, n_0, e)
	cipher_1 = utils.RSA_encrypt(message, n_1, e)
	cipher_2 = utils.RSA_encrypt(message, n_2, e)

	return cipher_0, n_0, cipher_1, n_1, cipher_2, n_2

def cube_root(x):
	decimal.getcontext().prec = 2 * len(str(x))
	power = decimal.Decimal(1) / decimal.Decimal(3)
	x = decimal.Decimal(str(x))
	root = x ** power

	integer_root = root.quantize(decimal.Decimal('1.'), rounding=decimal.ROUND_UP)
	return int(integer_root)

def broadcast_attack(cipher_0, n_0, cipher_1, n_1, cipher_2, n_2):
	c_0 = int(cipher_0.encode('hex'), 16)
	c_1 = int(cipher_1.encode('hex'), 16)
	c_2 = int(cipher_2.encode('hex'), 16)

	m_s_0 = n_1 * n_2
	m_s_1 = n_0 * n_2
	m_s_2 = n_0 * n_1

	result = (c_0 * m_s_0 * utils.invmod(m_s_0, n_0) + c_1 * m_s_1 * utils.invmod(m_s_1, n_1) + c_2 * m_s_2 * utils.invmod(m_s_2, n_2)) % (n_0 * n_1 * n_2)
	m = cube_root(result)

	xM = hex(m)[2:].strip('L')

	if len(xM) % 2 != 0:
		xM = '0' + xM

	return xM.decode('hex')

random.seed()
cipher_0, n_0, cipher_1, n_1, cipher_2, n_2 = get_three_ciphertexts()
message = broadcast_attack(cipher_0, n_0, cipher_1, n_1, cipher_2, n_2)

print message
