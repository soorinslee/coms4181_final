CC = gcc
CFLAGS = -g -Wall
LDFLAGS = -g

all : setcertificate getcertificate

setcertificate : setcertificate.o

getcertificate : getcertificate.o

setcertificate.o : setcertificate.c

getcertificate.o : getcertificate.c

.PHONY : clean
clean:
	rm -rf getcertificate setcertificate *.o *.a a.out
