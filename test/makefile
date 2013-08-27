CC=gcc

CRYPTO=../crypto

CFLAGS = -O0 -pedantic -std=c99 -Wall -g -D__LITTLE_ENDIAN=1 -I$(CRYPTO) -DAES -DAES_DECR -DAES_GCM -DAES_ECB -DAES_WRAP

test8: CFLAGS := $(CFLAGS) -D__WORD_SIZE=1
test8: test

test16: CFLAGS := $(CFLAGS) -D__WORD_SIZE=2
test16: test

test32: CFLAGS := $(CFLAGS) -D__WORD_SIZE=4
test32: test

test64: CFLAGS := $(CFLAGS) -D__WORD_SIZE=8
test64: test

test: test.o $(CRYPTO)/core.o
	$(CC) $^ -o test 

clean:
	$(RM) *.o $(CRYPTO)/*.o
