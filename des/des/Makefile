CC=gcc
OBJ = des.o main.o
CFLAGS = -g
%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

des: $(OBJ)
	$(CC) -o  $@ $^ $(CFLAGS)

clean:
	rm *.o des 
