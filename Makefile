
traas: tcpServer.o httpFormatter.o
	gcc -D_GNU_SOURCE -g -Wall -O2 -o traas tcpServer.o httpFormatter.o

