#include <stdio.h>
#include <sys/socket.h>
#include "icmpRecorder.h"

const char* get302();
int send404(int sock);
int send200(int sock, struct trace* trace);

