CC=gcc
dEPS = des.h
OBJ = 
CFLAGS = -g
%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

des: $(OBJ)
	$(CC) -o  $@ $^ $(CFLAGS)

clean:
	rm *.o des *.txt
