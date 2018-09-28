CC=gcc
DEPS = matrix.h aes.h math.h
OBJ = main.o s_block.o math.o matrix.o
CFLAGS = -lm -g

%.o: %.c $(DEPS)
	$(CC) -c -g -o $@ $< $(CFLAGS)

all: aes
aes: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm *.o
	rm aes
