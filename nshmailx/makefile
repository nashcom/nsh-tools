
############################################################################
# Copyright Nash!Com, Daniel Nashed 2024 - APACHE 2.0 see LICENSE
############################################################################


CC=gcc
CFLAGS= -g -Wall -c -fPIC -pedantic
LIBS=-lcrypto -lssl -lresolv

PROGRAM=nshmailx

all: $(PROGRAM)

$(PROGRAM): $(PROGRAM).o
	$(CC) -o $(PROGRAM) $(PROGRAM).o $(LIBS)

$(PROGRAM).o: $(PROGRAM).cpp
	$(CC)  $(CFLAGS) $(PROGRAM).cpp

clean:
	rm -f $(PROGRAM) *.o

test: all
	$(PROGRAM)

