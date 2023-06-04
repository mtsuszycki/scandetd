CFLAGS=-O2 -fomit-frame-pointer -malign-loops=2 -Wall -ggdb 
OBJ=scandetd.o config.o

BINDIR=/usr/sbin/
CONFIGDIR=/etc/

scandetd: $(OBJ)
	gcc -o scandetd $(OBJ) 
#	strip scandetd
clean: 
	rm -f ./*.o
	rm -f ./scandetd
install:
	install -m 700 -o root -g root ./scandetd $(BINDIR)
	install -m 644 -o root -g root ./scandetd.conf $(CONFIGDIR)