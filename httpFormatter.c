#include <string.h>
#include <netinet/in.h>
#include "httpFormatter.h"

const char* redirect = "HTTP/1.1 302 Found\r\n\
Location: /result.json\r\n\
Connection: Keep-Alive\r\n\r\n";

const char* notfound = "HTTP/1.1 404 Not Found\r\n";

const char* summary = "HTTP/1.1 200 OK\r\n\
Content-Type: application/json\r\n";

const char* get302() {
  return redirect;
};

int send200(int sock, struct trace* trace) {
  int cl;
  int hops, maxHops;
  char head[255];
  char buf[2048];
  unsigned short pos = 0;
  struct in_addr addr;
  maxHops = 64;
  pos += sprintf(buf, "[");

  while (hops < trace->recordedHops) {
    hops += 1;
    addr.s_addr = trace->hops[hops].ip;
    pos += sprintf(buf+pos, "{\"ttl\":%d, \"ip\":\"%s\"},\n", trace->hops[hops].ttl, inet_ntoa(addr));
  }
  int len = strlen(summary);
  send(sock, summary, len, 0);
  sprintf(buf+pos - 1, "]");
  cl = strlen(buf);
  sprintf(head, "Content-Length: %d\r\n\r\n", cl);
  send(sock, head, strlen(head), 0);
  send(sock, buf, strlen(buf), 0);
  return 0;
};

int send404(int sock) {
  send(sock, notfound, strlen(notfound), 0);
  return 0;
}