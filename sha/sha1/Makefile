CC=gcc
OBJ = sha1.o main.o
CFLAGS = -Wall -g
%.o: %.c $(DEPS)
	$(CC) -c $(CFLAGS) -o $@ $<

sha: $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^

clean:
	rm *.o sha
