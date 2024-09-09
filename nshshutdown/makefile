############################################################################
# Copyright Nash!Com, Daniel Nashed 2024 - APACHE 2.0 see LICENSE
############################################################################

NODEBUG=1

all: nshshutdown.exe
# Link command

nshshutdown.exe: nshshutdown.obj
	link /SUBSYSTEM:CONSOLE nshshutdown.obj msvcrt.lib user32.lib Shell32.lib Ws2_32.lib Advapi32.lib /PDB:$*.pdb /DEBUG /PDBSTRIPPED:$*_small.pdb -out:$@
	del $*.pdb $*.sym
	rename $*_small.pdb $*.pdb

# Compile command

nshshutdown.obj: nshshutdown.cpp
	cl -c /Zp /DWINVER=0x0602 nshshutdown.cpp /Fo"$@"
	cl -nologo -c -D_MT -MT /Zi /Ot /O2 /Ob2 /Oy- -Gd /Gy /GF /Gs4096 /GS-  /DWINVER=0x0602 /EHsc /Zc:wchar_t- -Zl -W1 nshshutdown.cpp

clean:
	del *.obj *.pdb *.exe *.ilk *.sym *.map *.res

