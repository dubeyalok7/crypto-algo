CC=gcc
DEPS = 
OBJ = openssl_example.o
CFLAGS = -lcrypto -lssl
INCLUDE = -I/home/napster/code/openssl/bindist/include
LDPATH = -L/home/napster/code/openssl/bindist/lib
%.o: %.c $(DEPS)
	$(CC) $(INCLUDE) $(LDPATH) -c -g -o $@ $< $(CFLAGS)

all: cmac_eg
cmac_eg: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

clean:
	rm *.o
	rm cmac_eg
