CC=gcc
DEPS = feistal.h
OBJ = feistal_algo.o

%.o: %.c $(DEPS)
	$(CC) -c -g -o $@ $< $(CFLAGS)

feistal: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)
	rm *.o

clean:
#	rm *.o
	rm feistal
