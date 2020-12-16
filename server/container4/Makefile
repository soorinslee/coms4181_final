CC = gcc
CFLAGS = -g -Wall
LDFLAGS = -g

all : hasmsg getnextmsg storemsg

hasmsg : hasmsg.o

getnextmsg : getnextmsg.o

storemsg : storemsg.o

hasmsg.o : hasmsg.c

getnextmsg.o : getnextmsg.c

storemsg.o : storemsg.c

.PHONY : clean
clean:
	rm -rf hasmsg getnextmsg storemsg *.o *.a a.out
