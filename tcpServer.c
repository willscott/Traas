/*
 * TCP Traceroute Server.
 *
 * Author: Will Scott (willscott@gmail.com) 2014
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <poll.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#define PORT 8080
#define MAX_PENDING 5
#define MAX_CONNECTIONS 9
#define MAX_LINE 256
#define MAX_QUEUE 256

#include "httpFormatter.h"

/* Data about a client */
int fs = 0, running = 1, error = 0;
int numcon;
struct clientData {
  int d; //file descriptor
  struct sockaddr_in cin;
  struct timeval start;
  size_t state;
  size_t left;
  void* data;
};

void leave(int s) {
  running = 0;
}

int main() {
  struct sockaddr_in sin;
  int s;
  socklen_t sinl;
  struct clientData clients[MAX_CONNECTIONS];
  int i, j, len;
  int sockopt, one = 1;
  char buf[MAX_LINE];
  struct pollfd fds[MAX_CONNECTIONS + 1];

  /* signals */
  signal (SIGINT, leave);
  signal (SIGTERM, leave);
  signal (SIGQUIT, leave);

  /* Ignore quitting clients */
  sigignore(SIGPIPE);

  /* build address data structure */
  bzero((char *)&sin, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = INADDR_ANY;
  sin.sin_port = htons(PORT);

  /* passive open */
  if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket");
    exit(1);
  }

  /* Make the socket non-blocking */
  setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
  if ((sockopt = fcntl(s, F_GETFL)) < 0) {
    perror("getting options");
    exit(1);
  }
  if ((fcntl(s, F_SETFL, (sockopt | O_NONBLOCK))) < 0) {
    perror("setting non-blocking");
    exit(1);
  }

  if ((bind(s, (struct sockaddr *)&sin, sizeof(sin))) < 0) {
    perror("bind");
    exit(1);
  }
  listen(s, MAX_PENDING);

  /* Open Listener */
  // TODO(willscott): pcap setup.

  /* Initialize connection information */
  for (i = 0; i < MAX_CONNECTIONS; ++i) {
    clients[i].d = 0;
    bzero((char *)&clients[i].cin, sizeof(clients[i].cin));
  }
  numcon = 0;

  while (running) {
    fds[0].fd = s;
    fds[0].events = POLLIN;
    for (i = 0; i < numcon; ++i) {
      fds[i + 1].fd = clients[i].d;
      fds[i + 1].events = POLLIN;
    }
    if (error > 0) {
      // TODO(willscott): Reset state.
      error = 0;
    }
    if (poll(fds, numcon + 1, 100)) {
      for (i = 0; i < numcon; ++i) {
        /* Read from an existing client */
        if (fds[i + 1].revents != 0) {
          //printf("got client event\n");
          len = recv(clients[i].d, buf, sizeof(buf), 0);
          //Disconnect
          if (len <= 0) {
            close(clients[i].d);
            for (j = i + 1; j < numcon; ++j) {
              clients[j - 1] = clients[j];
              fds[j - 1] = fds[j];
            }
            --numcon;
            --i;
          } else {
            if (clients[i].state == 0) { // no data read yet.
              if (strncasecmp("GET / ", buf, 6) == 0) {
                clients[i].state = 1;
              } else {
                // Summary statistics
                printf("Statsing\n");
                get200(clients[i].d);
                close(clients[i].d);
                for (j = i + 1; j < numcon; ++j) {
                  clients[j - 1] = clients[j];
                  fds[j - 1] = fds[j];
                }
                --numcon;
                --i;
              }
            }
            if (clients[i].state == 1) {
              if(strstr(buf, "\r\n\r\n") != 0) {
                clients[i].state = 3;
                clients[i].data = (void*)get302();
                clients[i].left = strlen((char*)clients[i].data);
                printf("End of Input!\n");
              } else if (strlen(buf) > 2 && strncmp(&buf[strlen(buf) - 2], "\r\n", 2) == 0) {
                clients[i].state = 2;
              }
            } else if (clients[i].state == 2 && strncmp(buf, "\r\n", 2) == 0) {
              clients[i].state = 3;
              clients[i].data = (void*)get302();
              clients[i].left = strlen((char*)clients[i].data);
              printf("End of Input!\n");
            } else if (clients[i].state == 2) {
              clients[i].state = 1;
            }

            // Start attempts to send response.
            if (clients[i].state == 3) {
              clients[i].left -= send(clients[i].d, clients[i].data, clients[i].left, 0);
              printf("sending 302 - %u bytes remaining\n", clients[i].left);
              if (clients[i].left <= 0) {
                printf("done\n");
                clients[i].state = 0;
              }
            }
          }
        }
      }
      if (fds[0].revents != 0 && numcon < MAX_CONNECTIONS) {
        /* Accept new Clients */
        printf("will accept...");
        sinl = sizeof(clients[numcon].cin);
        if ((clients[numcon].d = accept(s,
            (struct sockaddr *)&clients[numcon].cin, &sinl)) < 0) {
          perror("client accept failure");
          exit(1);
        }
        gettimeofday(&clients[numcon].start, NULL);
        printf("accepted\n");
        clients[numcon].state = 0;
        if ((sockopt = fcntl(s, F_GETFL)) < 0) {
          perror("client options failure");
          exit(1);
        }
        if ((fcntl(s, F_SETFL,(sockopt | O_NONBLOCK))) < 0) {
          perror("client non-blocking failure");
          exit(1);
        }
        numcon++;
      }
    }
  }

  /* Cleanup */
  return 0;
}

