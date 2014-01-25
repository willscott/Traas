#include <sys/socket.h>
#include <stdint.h>
#include <netinet/in.h>

struct hop {
  uint8_t ttl;
  
};

int beginCapture();
void processPcap();

char* beginTrace(struct sockaddr_in* to);

struct hop* infoFor(char* id);

