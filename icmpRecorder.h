#include <pcap.h>
#include <sys/socket.h>
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#ifndef   ICMP_H
#define   ICMP_H

#define MAX_HOPS 32

struct hop {
  uint8_t ttl;
  int ip;
  size_t len;
};

struct trace {
  int to;
  unsigned short recordedHops;
  struct hop hops[MAX_HOPS];
};

struct seqreq {
  int to;
  int seq;
};

struct pktinfo {
  // IP
  struct ip iphdr;
  // ICMP
  unsigned char type;
  unsigned char code;
  unsigned short i_checksum;
  unsigned int padding;
  // IP [inner]
  struct ip eiphdr;
  // TCP [inner]
  unsigned short sport;
  unsigned short dport;
  unsigned int seq;
  unsigned int ack;
  unsigned short flags;
  unsigned short winsize;
  unsigned short tcp_sum;
};

int beginCapture();
void processPcap();
void handlePcap(u_char *user, const struct pcap_pkthdr * header, const u_char *bytes);

void* beginTrace(int d, struct sockaddr_in* to);

struct hop* showTrace(void* id);
void cleanupTrace(void* id);

#endif
