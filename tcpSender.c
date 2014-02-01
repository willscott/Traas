#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include <netinet/in.h>
#include "tcpSender.h"

int osock;
void initSender() {
  int b;
  struct linger linger;

  osock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

  // Allow reuse
  setsockopt(osock, SOL_SOCKET, SO_REUSEADDR, &b, sizeof(b));
  // Close fast
  linger.l_onoff = 0;
  setsockopt(osock, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger));
};

void craftPkt(unsigned int to, unsigned int seq) {
  struct sockaddr_in dest;
  char* data;
  dest.sin_family = AF_INET;
  dest.sin_addr.s_addr = to;
  dest.sin_port = 8080;

  if(sendto(osock, data, strlen(data), 0, (struct sockaddr*)&dest, sizeof(dest)) == -1) {
    printf("sendto() failed");
  }
};
