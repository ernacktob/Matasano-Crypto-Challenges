import base64
import os
import random
import zlib

import crypto_utils as utils

# This challenge is interesting because it models the CRIME attack on TLS...

def stream_encrypt(M):
	return "".join([chr(ord(c) ^ random.randint(0, 255)) for c in M])

def cbc_encrypt(M):
	key = os.urandom(utils.BLOCK_SIZE)
	iv = os.urandom(utils.BLOCK_SIZE)
	return utils.aes_cbc_encrypt(utils.PKCS7_Pad(M), key, iv)

def compress(data):
	return zlib.compress(data)

def format_request(P):
	return "POST / HTTP/1.1\r\nHost: hapless.com\r\nCookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=\r\nContent-Length: %d\r\n%s"%(len(P), P)

def stream_oracle(P):
	return len(stream_encrypt(compress(format_request(P))))

def cbc_oracle(P):
	return len(cbc_encrypt(compress(format_request(P))))

def recover_sessionid_recurse(oracle, prefix):
	if prefix.endswith("\r\n"):
		return [""]

	# For CBC: if the compression reduces the length within
	# a 16-byte block, the padding will round it off and hide that.
	# So we add some filler at the end until the compressed data is
	# crosses a block boundary to become detectable.
	for fillerlen in range(utils.BLOCK_SIZE):		
		filler = os.urandom(fillerlen)
		different = False
		min_len = -1

		for i in range(256):
			l = oracle(prefix + chr(i) + filler)

			if min_len != -1 and l != min_len:
				different = True

			if l < min_len or min_len == -1:
				min_len = l

		if different == True:
			break

	candidates = []

	for i in range(256):
		if oracle(prefix + chr(i) + filler) == min_len:
			suffixes = recover_sessionid_recurse(oracle, prefix + chr(i))
			candidates.extend([chr(i) + suffix for suffix in suffixes])

	return candidates

def recover_sessionid(oracle):
	# Start with a "Cookie: sessionid=" prefix to ignore repeats due to other strings
	# such as "Host: hapless.com", etc.
	sessionids = recover_sessionid_recurse(oracle, "Cookie: sessionid=")
	sessionids = [sessionid[:-2] for sessionid in sessionids]

	return sessionids

sessionids1 = recover_sessionid(stream_oracle)
sessionids2 = recover_sessionid(cbc_oracle)
print sessionids1
print sessionids2
print base64.b64decode(sessionids1[0])
