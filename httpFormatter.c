#include <string.h>
#include <netinet/in.h>
#include "httpFormatter.h"

const char* redirect = "HTTP/1.1 302 Found\r\n\
Location: /result.json\r\n\
Connection: Keep-Alive\r\n\
Content-Length: 0\r\n\r\n";

const char* notfound = "HTTP/1.1 404 Not Found\r\n";

const char* summary = "HTTP/1.1 200 OK\r\n\
Content-Type: application/json\r\n";

const char* get302() {
  return redirect;
};

int send200(int sock, struct trace* trace) {
  int cl;
  char head[255];
  char buf[4096];
  cl = getjson(buf, trace);

  int len = strlen(summary);
  send(sock, summary, len, 0);
  sprintf(head, "Content-Length: %d\r\n\r\n", cl);
  send(sock, head, strlen(head), 0);
  send(sock, buf, strlen(buf), 0);
  return 0;
};

int getjson(char* buffer, struct trace* trace) {
  unsigned short hops = 0, pos = 0, ttl;
  struct in_addr addr;

  addr.s_addr = trace->to;
  pos += sprintf(buffer, "{\"to\":\"%s\", \"hops\":[", inet_ntoa(addr));

  while (hops < trace->recordedHops) {
    hops += 1;
    addr.s_addr = trace->hops[hops].ip;
    ttl = trace->hops[hops].ttl;
    if (ttl < 64) {
      ttl = 64 - ttl;
    } else if (ttl < 255) {
      ttl = 255 - ttl;
    }
    pos += sprintf(buffer + pos,
        "{\"ttl\":%d, \"ip\":\"%s\"},", ttl, inet_ntoa(addr));
  }
  if (trace->recordedHops == 0) {
    pos += sprintf(buffer + pos, " ");
  }
  sprintf(buffer + pos - 1, "]}");
  return strlen(buffer);
};

int send404(int sock) {
  send(sock, notfound, strlen(notfound), 0);
  return 0;
}