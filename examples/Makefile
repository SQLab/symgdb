all: crackme_xor crackme_hash

crackme_xor: crackme_xor.cpp
	g++ -m32 crackme_xor.cpp -o crackme_xor_32
	g++ crackme_xor.cpp -o crackme_xor_64

crackme_hash: crackme_hash.cpp
	g++ -m32 crackme_hash.cpp -o crackme_hash_32
	g++ crackme_hash.cpp -o crackme_hash_64

clean:
	rm -rf crackme_xor_32 crackme_xor_64 crackme_hash_32 crackme_hash_64
