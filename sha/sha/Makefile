CC=gcc
DEPS = sha.h sha_private.h
OBJ = sha1.o sha224_256.o sha384_512.o usha.o main.o
CFLAGS = -Wall -g
%.o: %.c $(DEPS)
	$(CC) -c $(CFLAGS) -o $@ $<

sha: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm *.o sha
