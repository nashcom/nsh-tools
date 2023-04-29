
############################################################################
# Copyright Nash!Com, Daniel Nashed 2023 - APACHE 2.0 see LICENSE
############################################################################


CC=g++
CFLAGS= -g -Wall -c -fPIC -fpermissive -Wno-write-strings
LIBS= -lcrypto -lssl

PROGRAM=nshciphers

all: $(PROGRAM)

$(PROGRAM): $(PROGRAM).o
	$(CC) -o $(PROGRAM) $(PROGRAM).o $(LIBS) -o bin/$(PROGRAM)

$(PROGRAM).o: $(PROGRAM).cpp
	$(CC)  $(CFLAGS) $(PROGRAM).cpp -DLINUX -DUNIX

clean:
	rm -f bin/$(PROGRAM) *.o

test: all
	bin/$(PROGRAM)

install: all
	sudo cp bin/$(PROGRAM) /usr/bin/$(PROGRAM)
	$(MAKE) clean

uninstall:
	sudo rm -f /usr/bin/$(PROGRAM)
	$(MAKE) clean
