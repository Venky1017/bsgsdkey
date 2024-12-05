CC = gcc
CFLAGS = -O2 -Wall -Wextra
LIBS = -lssl -lcrypto

all: bsgsd

bsgsd: bsgsd.c
	$(CC) $(CFLAGS) -o bsgsdkey bsgsd.c $(LIBS)

clean:
	rm -f bsgsd
