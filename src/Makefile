CC=gcc
CPP=g++
CPP_FLAGS=-I. 
# -Wall -pedantic
DEPS = 
HEADERS = config.h distorm.h decoder.h instructions.h insts.h mnemonics.h operands.h prefix.h textdefs.h wstring.h x86defs.h parse.h to_string.h nt-headers.h argh.h
OBJ = decoder.o distorm.o instructions.o insts.o main.o mnemonics.o operands.o prefix.o textdefs.o buffer.o parse.o unicode_winapi.o
 
all: $(OBJ)
	$(CPP) -o distorm3 $^ $(CPP_FLAGS)
	
decoder.o : decoder.c
	$(CPP) -c -o $@ $< $(CPP_FLAGS)
distorm.o : distorm.c
	$(CPP) -c -o $@ $< $(CPP_FLAGS)	
instructions.o : instructions.c
	$(CPP) -c -o $@ $< $(CPP_FLAGS)
insts.o : insts.c
	$(CPP) -c -o $@ $< $(CPP_FLAGS)
main.o : main.cpp
	$(CPP) -c -o $@ $< $(CPP_FLAGS)
mnemonics.o : mnemonics.c
	$(CPP) -c -o $@ $< $(CPP_FLAGS)
operands.o : operands.c
	$(CPP) -c -o $@ $< $(CPP_FLAGS)

prefix.o : prefix.c
	$(CPP) -c -o $@ $< $(CPP_FLAGS)
textdefs.o : textdefs.c
	$(CPP) -c -o $@ $< $(CPP_FLAGS)
buffer.o : buffer.cpp
	$(CPP) -c -o $@ $< $(CPP_FLAGS)
parse.o : parse.cpp
	$(CPP) -c -o $@ $< $(CPP_FLAGS)
unicode_winapi.o : unicode_winapi.cpp
	$(CPP) -c -o $@ $< $(CPP_FLAGS)

clean:
	rm -rf *.o
	rm -rf distorm3.exe
	rm -rf distorm3