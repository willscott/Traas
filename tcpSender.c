#include <errno.h>
#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include "tcpSender.h"

struct tcp_pseudohdr {
  unsigned int src;
  unsigned int dst;
  unsigned char zeros;
  unsigned char proto;
  unsigned short len;
};

#define TCPHSIZE 20
#define PTCPHSIZE 12
#define IPHSIZE 20

unsigned short checksum(unsigned short *buffer, int size) {
  // convert from num bytes to num shorts.
  size = size >> 1;
  unsigned long cksum = 0;
  while(size > 1) {
    cksum += *buffer++;
    size -= sizeof(unsigned short);
  }
  if(size)
    cksum += *(unsigned char*)buffer;

  cksum = (cksum >> 16) + (cksum & 0xffff);
  cksum += (cksum >>16);
  return (unsigned short)(~cksum);
}

int osock;
struct ifreq ifr;

void initSender() {
  int b;
  struct linger linger;

  printf("making raw socket.\n");
  osock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  if (osock == -1) {
    printf("Socket() failed.\n");
    return;
  }

  // Allow reuse
  b = 1;
  if(setsockopt(osock, SOL_SOCKET, SO_REUSEADDR, &b, sizeof(b)) == -1) {
    printf("reuseAddr failed.\n");
  }
  // Close fast
  linger.l_onoff = 0;
  if(setsockopt(osock, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger)) == -1) {
    printf("linger off failed.\n");
  }
  // We do Header
  b = 1;
  if(setsockopt(osock, IPPROTO_IP, IP_HDRINCL, &b, sizeof(b)) == -1) {
    printf("setsockopt() failed.\n");
    return;
  }

  // Select device (linux)
#ifdef SIOCGIFINDEX
  memset(&ifr, 0, sizeof(ifr));
  memcpy(ifr.ifr_name, "eth2", 4);
  if(ioctl(osock, SIOCGIFINDEX, &ifr) < 0) {
    printf("ioctl failed.\n");
    return;
  }
  if(setsockopt(osock, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
    printf("bind failed.\n");
    return;
  }
#endif

};

void craftPkt(unsigned int to, unsigned short port, unsigned int from, unsigned int seq, unsigned char ttl) {
  char* payload = "PING";

  struct sockaddr_in dest;
  char data[4096];
  struct ip* ip_hdr = (struct ip*) data;
  struct tcphdr* tcp_hdr = (struct tcphdr*) (data + sizeof(struct ip));
  struct tcp_pseudohdr* fake_hdr = (struct tcp_pseudohdr*)
      (data + sizeof(struct ip) - sizeof(struct tcp_pseudohdr));
  unsigned short plen = strlen(payload);
  memset(data, 0, sizeof(data));
  dest.sin_family = AF_INET;
  dest.sin_addr.s_addr = to;
  dest.sin_port = port;

  /* Fill in TCP */
  tcp_hdr->th_sport = htons(8080);
  tcp_hdr->th_dport = port;
  tcp_hdr->th_seq = seq;
  tcp_hdr->th_ack = 0;
  tcp_hdr->th_win = htons(65535);
  tcp_hdr->th_sum = 0;
  tcp_hdr->th_off = 5;

  /* Fill in Pseudo header */
  fake_hdr->src = from;
  fake_hdr->dst = to;
  fake_hdr->zeros = 0;
  fake_hdr->proto = 6;
  fake_hdr->len = htons(TCPHSIZE);

  /* Fill in payload */
  memcpy(data + IPHSIZE + TCPHSIZE, payload, plen);

  /* Compute TCP Checksum */
  tcp_hdr->th_sum = checksum((unsigned short *) fake_hdr, TCPHSIZE + PTCPHSIZE + plen);

  /* Revert Pseudo header */
  memset(data, 0, sizeof(struct ip));

  /* Fill in IP */
  ip_hdr->ip_hl = 5;
  ip_hdr->ip_v = 4;
  ip_hdr->ip_tos = 0;
  // packet len filled in by kernel.
  // ip_hdr->ip_len = htons(IPHSIZE + TCPHSIZE);
  // packet id filled in when 0
  // ip_hdr->ip_id = 0x1000;
  ip_hdr->ip_off = 0;
  ip_hdr->ip_ttl = ttl; //TTL
  ip_hdr->ip_p = 6;
  ip_hdr->ip_sum = 0;
  // source address filled in when 0
  //  ip_hdr->ip_src.s_addr = from;
  ip_hdr->ip_dst.s_addr = to;

  /* Compute IP Checksum */
  // ip checksum auto-calculated by kernel.
  //ip_hdr->ip_sum = checksum((unsigned short *)data, IPHSIZE);

  printf("Attempting to send pkt with args: %d, %d, 0, %d", osock, IPHSIZE + TCPHSIZE + plen, sizeof(dest));

  if(sendto(osock, data, IPHSIZE + TCPHSIZE + plen, 0, (struct sockaddr*)&dest, sizeof(dest)) == -1) {
    int errsv = errno;
		perror("sendto");
    printf("sendto() failed: %d\n", errsv);
  }
};
