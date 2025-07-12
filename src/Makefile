CC=gcc
CFLAGS=-I. 
# -Wall -pedantic
DEPS = 
HEADERS = config.h distorm.h decoder.h instructions.h insts.h mnemonics.h operands.h prefix.h textdefs.h wstring.h x86defs.h
OBJ = decoder.o distorm.o instructions.o insts.o main.o mnemonics.o operands.o prefix.o textdefs.o
 
all: $(OBJ)
	$(CC) -o distorm3 $^ $(CFLAGS)
	
decoder.o : decoder.c
	$(CC) -c -o $@ $< $(CFLAGS)
distorm.o : distorm.c
	$(CC) -c -o $@ $< $(CFLAGS)	
instructions.o : instructions.c
	$(CC) -c -o $@ $< $(CFLAGS)
insts.o : insts.c
	$(CC) -c -o $@ $< $(CFLAGS)
main.o : main.c
	$(CC) -c -o $@ $< $(CFLAGS)
mnemonics.o : mnemonics.c
	$(CC) -c -o $@ $< $(CFLAGS)
operands.o : operands.c
	$(CC) -c -o $@ $< $(CFLAGS)
prefix.o : prefix.c
	$(CC) -c -o $@ $< $(CFLAGS)
textdefs.o : textdefs.c
	$(CC) -c -o $@ $< $(CFLAGS)


	
clean:
	rm -rf *.o
	rm -rf distorm3.exe