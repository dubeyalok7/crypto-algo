CC=gcc
DEPS = global.h md5.h
OBJ = md5c.o mddriver.o 

%.o: %.c $(DEPS)
	$(CC) -c -g -o $@ $< $(CFLAGS)

md5: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)
	rm *.o

clean:
#	rm *.o
	rm md5
