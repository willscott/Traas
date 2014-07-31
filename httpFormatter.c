#include <string.h>
#include "httpFormatter.h"

const char* redirect = "HTTP/1.1 302 Found\r\n\
Location: /result.json\r\n\
Connection: Keep-Alive\r\n\r\n";

const char* summary = "HTTP/1.1 200 OK\r\n\
Content-Type: Text/html\r\n";

const char* templ = "[]";

const char* get302() {
  return redirect;
};

int send200(int sock) {
  int cl;
  char buf[255];
  int len = strlen(summary);
  send(sock, summary, len, 0);
  cl = strlen (templ);
  sprintf(buf, "Content-Length: %d\r\n\r\n", cl);
  send(sock, buf, strlen(buf), 0);
  send(sock, templ, strlen(templ), 0);
  return 0;
};
