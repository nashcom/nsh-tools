############################################################################
# Copyright Nash!Com, Daniel Nashed 2024 - APACHE 2.0 see LICENSE
############################################################################

CC=gcc
CFLAGS= -g -Wall -c -fPIC -pedantic
LIBS=-lcrypto -lssl -lresolv

# Needed on MacOS for LibreSSL compile and link. Does not harm other platforms
MACOS_LIBRE_SSL_INCLUDE_PATH=-I/opt/local/include
MACOS_LIBRE_SSL_LIB_PATH=-L/opt/local/lib

PROGRAM=nshmailx

all: $(PROGRAM)

$(PROGRAM): $(PROGRAM).o
	$(CC) -o $(PROGRAM) $(PROGRAM).o $(LIBS) $(MACOS_LIBRE_SSL_LIB_PATH)

$(PROGRAM).o: $(PROGRAM).cpp
	$(CC)  $(CFLAGS) $(PROGRAM).cpp $(MACOS_LIBRE_SSL_INCLUDE_PATH)

clean:
	rm -f $(PROGRAM) *.o

test: all
	./$(PROGRAM) --version
