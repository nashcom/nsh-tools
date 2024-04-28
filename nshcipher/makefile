
############################################################################
# Copyright Nash!Com, Daniel Nashed 2023 - APACHE 2.0 see LICENSE
############################################################################


CC=g++
CFLAGS=-g -Wall -c -fPIC -pedantic -O2

# If OpenSSL statically linked is available compile and link statically with it
ifneq (,$(wildcard ../../openssl/libssl.a))

LIBS=../../openssl/libssl.a ../../openssl/libcrypto.a  -lresolv
SSL_INCLUDE_PATH=-I../../openssl/include

$(info )
$(info Build with OpenSSL statically linked)
$(info )

# On MacOS if LibreSSL is available, statically with it
else ifneq (,$(wildcard /opt/local/lib/libssl.a))

LIBS=/opt/local/lib/libssl.a /opt/local/lib/libcrypto.a -lresolv
SSL_INCLUDE_PATH=-I/opt/local/include

$(info )
$(info Build with LibreSSL statically linked)
$(info )
$(info Some TLS/SSL logging functionality is not available on LibreSSL.)
$(info Consider using statically linked OpenSSL instead.)
$(info )

# Else just link dynamically with OpenSSL
else

LIBS= -lcrypto -lssl -lresolv

$(info )
$(info Build with OpenSSL dynamically linked)
$(info )

endif

PROGRAM=nshciphers

all: $(PROGRAM)

$(PROGRAM): $(PROGRAM).o
	$(CC) $(PROGRAM).o $(LIBS) -o $(PROGRAM)

$(PROGRAM).o: $(PROGRAM).cpp
	$(CC)  $(CFLAGS) $(PROGRAM).cpp -DLINUX -DUNIX $(SSL_INCLUDE_PATH)

clean:
	rm -f $(PROGRAM) *.o

test: all
	./$(PROGRAM)

install: all
	sudo cp $(PROGRAM) /usr/bin/$(PROGRAM)
	$(MAKE) clean

uninstall:
	sudo rm -f /usr/bin/$(PROGRAM)
	$(MAKE) clean
