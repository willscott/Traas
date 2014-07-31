traas: tcpServer.o httpFormatter.o icmpRecorder.o tcpSender.o
	gcc -D_GNU_SOURCE -g -Wall -o traas tcpServer.o httpFormatter.o icmpRecorder.o tcpSender.o -lpcap

icmpRecorder.o: icmpRecorder.c
	gcc -c -g -o icmpRecorder.o icmpRecorder.c -lpcap

