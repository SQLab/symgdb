#!/bin/bash
DIR=$(dirname "$(readlink -f "$0")")
gdb -x $DIR/crackme_hash_32 $DIR/../examples/crackme_hash_32
gdb -x $DIR/crackme_hash_64 $DIR/../examples/crackme_hash_64
