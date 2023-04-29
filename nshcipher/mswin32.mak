# makefile
# Nash!Com / Daniel Nashed
# Windows 32-bit version using
# Microsoft Visual Studio 2017


NODEBUG=1

all: nshciphers.exe 
# Link command

nshciphers.exe: nshciphers.obj
	link /SUBSYSTEM:CONSOLE /LARGEADDRESSAWARE nshciphers.obj libcrypto.lib libssl.lib -out:$@ -MAP

# Compile command

nshcipher.obj: nshcipher.cpp
	cl -c /Zp /DWINVER=0x0602 nshcipher.cpp /Fo"$@"

clean:
	del *.obj *.pdb *.exe *.ilk *.sym *.map *.res

