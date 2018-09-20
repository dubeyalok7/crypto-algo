CC=gcc
OBJ = feistal.o feistal_encrypt.o feistal_decrypt.o keymgmt.o main.o
CFLAGS = -g
%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

feistal: $(OBJ)
	$(CC) -o  $@ $^ $(CFLAGS)

clean:
	rm *.o feistal *.txt
