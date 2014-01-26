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
  struct hop hops[MAX_HOPS];
};

int beginCapture();
void processPcap();

void* beginTrace(struct sockaddr_in* to);

struct hop* showTrace(void* id);
void cleanupTrace(void* id);

