CC=gcc
DEPS = keygen.h math.h
OBJ = keygen.o rsa_crypto.o math.o main.o
CFLAGS = -lm -g

%.o: %.c $(DEPS)
	$(CC) -c -g -o $@ $< $(CFLAGS)

all: rsa
rsa: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm *.o
	rm rsa
