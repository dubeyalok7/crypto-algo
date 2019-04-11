CC=gcc
#DEPS = sha.h sha_private.h
#OBJ = sha1.o sha224_256.o sha384_512.o usha.o hmac.o hkdf.o main.o
DEPS = sha256.h
OBJ = sha256.o main.o
CFLAGS = -Wall -Werror
%.o: %.c $(DEPS)
	$(CC) -g -c $(CFLAGS) -o $@ $<

sha: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm *.o sha
