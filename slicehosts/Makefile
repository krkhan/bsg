EXES = $(basename $(wildcard *.c))
CC = cc
CFLAGS = -Wall -g `pkg-config --cflags --libs glib-2.0` -lpcap

all: 
	$(MAKE) $(EXES)

%: %.c
	$(CC) $(CFLAGS) $@.c -o $@

clean:
	rm -f $(EXES) *.o

