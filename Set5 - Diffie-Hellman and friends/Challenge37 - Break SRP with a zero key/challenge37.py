import hashlib
import socket

import crypto_utils as utils

def recvline(s):
	line = ""

	while True:
		data = s.recv(1)

		if len(data) == 0:
			break

		if data == '\n':
			return line

		line += data

	return line

def SHA256_HASH(data):
	sha256 = hashlib.sha256()
	sha256.update(data)
	return sha256.digest()

N = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
g = 2
k = 3
I = "test@gmail.com"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
s.connect(('localhost', 9000))

line = I + " " + str(N)
print line
s.send(line + "\n")

line = recvline(s)
print line
salt = int(line.split(' ')[0])

K = SHA256_HASH(str(0))
hmac = utils.HMAC(str(salt), K, SHA256_HASH, hashlib.sha256().block_size)

line = hmac.encode('hex')
print line
s.send(line + "\n")

print recvline(s)
s.close()
