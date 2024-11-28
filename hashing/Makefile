CC=gcc
DEPS = global.h md5.h
OBJ = md5c.o mddriver.o hmac.o main.o

%.o: %.c $(DEPS)
	$(CC) -c -g -o $@ $< $(CFLAGS)

hash: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm *.o
	rm hash
