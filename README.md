# Matasano-Crypto-Challenges

This is currently a work in progress. I will gradually upload my solutions for the Matasano Crypto Challenges, a series of challenges centered on breaking modern crypto with common implementation mistakes. I code mostly in C, except for the web servers which I usually write in Python. I am also using Python for the number-theoretic crypto sets since it already has a built-in bignum feature. I unfortunately haven't put too much effort in commenting the code, and code quality may not always be great, but the point for me was more about the crypto than the coding.

I try to minimize the use of external libraries, but I used openssl/aes for the AES encryption.
Code that uses this library links with libcrypto.

To build a specific challenge, just run ./build.sh in the respective folder.

The challenges can be found here: http://cryptopals.com

Current status: Sets 1 to 7 completed.
