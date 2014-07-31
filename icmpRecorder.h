#include <sys/socket.h>
#include <stdint.h>
#include <netinet/in.h>

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
  unsigned int version : 4;
  unsigned int ihl : 4;
  unsigned int dscp : 6;
  unsigned int ecn : 2;
  unsigned short length;
  unsigned short id;
  unsigned short fragment;
  unsigned char ttl;
  unsigned char proto;
  unsigned short checksum;
  unsigned int source;
  unsigned int dest;
  // ICMP
  unsigned char type;
  unsigned char code;
  unsigned short i_checksum;
  unsigned int padding;
  // IP [inner]
  unsigned int e_version : 4;
  unsigned int e_ihl : 4;
  unsigned int e_dscp : 6;
  unsigned int e_ecn : 2;
  unsigned short e_length;
  unsigned short e_id;
  unsigned short e_fragment;
  unsigned char e_ttl;
  unsigned char e_proto;
  unsigned short e_checksum;
  unsigned int e_source;
  unsigned int e_dest;
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

void* beginTrace(struct sockaddr_in* to);

struct hop* showTrace(void* id);
void cleanupTrace(void* id);

void craftPkt(unsigned int to, unsigned int seq);
