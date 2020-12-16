CC = gcc
CFLAGS = -g -Wall
LDFLAGS = -g

all : isuservalid changepwd

isuservalid : isuservalid.o

changepwd : changepwd.o

isuservalid.o : isuservalid.c

changepwd.o : changepwd.c

.PHONY : clean
clean:
	rm -rf isuservalid changepwd *.o *.a a.out




