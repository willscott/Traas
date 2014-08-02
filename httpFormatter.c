#include <string.h>
#include "httpFormatter.h"

const char* redirect = "HTTP/1.1 302 Found\r\n\
Location: /result.json\r\n\
Connection: Keep-Alive\r\n\r\n";

const char* summary = "HTTP/1.1 200 OK\r\n\
Content-Type: Text/html\r\n";

const char* get302() {
  return redirect;
};

int send200(int sock, struct hop* trace) {
  int cl;
  int hops, maxHops;
  char head[255];
  char buf[2048];
  maxHops = 255;
  while (&trace != 0 && hops < maxHops) {
    hops += 1;
    trace += 1;
  }
  int len = strlen(summary);
  send(sock, summary, len, 0);
  sprintf(buf, "[%d hops]", hops);
  cl = strlen(buf);
  sprintf(head, "Content-Length: %d\r\n\r\n", cl);
  send(sock, head, strlen(head), 0);
  send(sock, buf, strlen(buf), 0);
  return 0;
};
