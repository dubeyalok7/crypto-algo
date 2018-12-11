CC=gcc
DEPS =
OBJ = main.o
CFLAGS = -lm -g

%.o: %.c $(DEPS)
	$(CC) -c -g -o $@ $< $(CFLAGS)

all: prng
prng: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm *.o
	rm prng
