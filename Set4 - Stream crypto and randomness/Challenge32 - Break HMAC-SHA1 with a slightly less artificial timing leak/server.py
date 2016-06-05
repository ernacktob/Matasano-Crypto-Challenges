import hashlib
import os
import re
import select
import signal
import socket
import time

STOP = False
HMAC_KEY = None

def sigint_handler(signum, frame):
	global STOP
	STOP = True

def insecure_compare(a, b):
	if len(a) != len(b):
		return 1

	for i in range(len(a)):
		if a[i] != b[i]:
			return 1

		# Can currently crack it for delays of 1ms
		time.sleep(0.001)

	return 0

def gen_HMAC_key():
	global HMAC_KEY
	length = int(os.urandom(1).encode('hex'), 16) + 1
	HMAC_KEY = os.urandom(length)

def send_error(s):
	error_msg = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"
	s.send(error_msg)

def send_auth_success(s):
	http = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n"
	html = "<html><head><title>Congratulations</title></head><body>Signature has been successfully authenticated.</body></html>"
	s.send(http + html + "\r\n")

def send_auth_failure(s):
	http = "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html\r\nConnection: close\r\n\r\n"
	html = "<html><head><title>Failure</title></head><body>Signature could not be authenticated.</body></html>"
	s.send(http + html + "\r\n")

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

def SHA1_HASH(data):
	hasher = hashlib.sha1()
	hasher.update(data)
	return hasher.digest()

def check_authentication(filename, signature):
	global HMAC_KEY

	try:
		signature = signature.decode('hex')
		f = open(filename, 'r')
		data = f.read()
		f.close()
	except:
		return False

	hmac = HMAC(data, HMAC_KEY, SHA1_HASH, hashlib.sha1().block_size)

	if insecure_compare(hmac, signature) == 0:
		return True

	return False

def process_request(s):
	http_data = s.recv(10000)

	while '\r\n' not in http_data and STOP == False:
		data = s.recv(1000)

		if len(data) == 0:
			return None

		http_data += data

	lines = re.sub("\r\n", "\n", http_data).split('\n')
	fields = lines[0].split(' ')

	if len(fields) != 3:
		return None

	method = fields[0]
	url = fields[1]
	proto = fields[2]

	if proto != 'HTTP/2.0' and proto != 'HTTP/1.1' and proto != 'HTTP/1.0':
		return None

	if method != 'GET':
		return None

	if '/' not in url:
		return None

	path = url.split('/')

	if len(path) > 2:
		return None

	stuff = path[1]

	if '?' not in stuff:
		return None

	page = stuff.split('?')[0]

	if page != 'test':
		return None

	params1 = stuff.split('?')[1]
	params1 = params1.split('&')
	params = {}

	for param in params1:
		if '=' not in param:
			return None

		key = param.split('=')[0]
		value = param.split('=')[1]
		params[key] = value
	
	if 'file' not in params or 'signature' not in params:
		return None

	return params

gen_HMAC_key()
server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
server_sock.bind(('localhost', 9000))
server_sock.listen(10)

signal.signal(signal.SIGINT, sigint_handler)

count = 0
while STOP == False:
	count += 1

	client_sock, client_addr = server_sock.accept()
	params = process_request(client_sock)

	if params == None:
		send_error(client_sock)
	else:
		if check_authentication(params['file'], params['signature']) == True:
			send_auth_success(client_sock)
		else:
			send_auth_failure(client_sock)

	client_sock.close()
	client_sock = None

if client_sock != None:
	client_sock.close()

server_sock.close()
