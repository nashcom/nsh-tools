############################################################################
# Copyright Nash!Com, Daniel Nashed 2024 - APACHE 2.0 see LICENSE
############################################################################

CC=gcc
CFLAGS=-g -Wall -c -fPIC -pedantic

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


PROGRAM=nshmailx

all: $(PROGRAM)

$(PROGRAM): $(PROGRAM).o
	$(CC) -o $(PROGRAM) $(PROGRAM).o $(LIBS)

$(PROGRAM).o: $(PROGRAM).cpp
	$(CC)  $(CFLAGS) $(PROGRAM).cpp $(SSL_INCLUDE_PATH) -O2

install: all
	sudo cp -f $(PROGRAM) /usr/bin/nshmailx

mailx: install
	sudo ln -s -f /usr/bin/nshmailx /usr/bin/mailx
	sudo ln -s -f /usr/bin/nshmailx /usr/bin/mail

clean:
	rm -f $(PROGRAM) *.o

test: all
	./$(PROGRAM) --version

publish: all
	mkdir -p /local/software/nashcom.de/linux-bin
	cp -f ./$(PROGRAM) /local/software/nashcom.de/linux-bin

