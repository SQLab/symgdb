#!/bin/bash
DIR=$(dirname "$(readlink -f "$0")")
TESTS=(crackme_hash_32 crackme_hash_64 crackme_xor_32 crackme_xor_64)
for program in "${TESTS[@]}"
do
  gdb -x $DIR/$program $DIR/../examples/$program
done
