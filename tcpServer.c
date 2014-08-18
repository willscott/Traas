/*
 * TCP Traceroute Server.
 *
 * Author: Will Scott (willscott@gmail.com) 2014
 */

#include <errno.h>
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
#include <time.h>

#include "tcpServer.h"
#include "httpFormatter.h"
#include "icmpRecorder.h"

/* Data about a client */
int fs = 0, running = 1, error = 0;
int numcon;
struct clientData {
  int d; //file descriptor
  struct sockaddr_in cin;
  struct timeval start;
  /*
   * state = 0 -> new connection
   * state = 1 -> client has asked for 'get'
   * state = 2 -> 
   */
  size_t state;
  size_t left;
  void* data;
  void* traceid;
  long unsigned delay;
};

void leave(int s) {
  running = 0;
}

int main() {
  struct sockaddr_in sin;
  int s, pcapfd;
  socklen_t sinl;
  struct clientData clients[MAX_CONNECTIONS];
  int i, j, len;
  int sockopt, one = 1;
  struct timeval now;
  char buf[MAX_LINE];
  struct pollfd fds[MAX_CONNECTIONS + 2];

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

  pcapfd = beginCapture();

  while (running) {
    fds[0].fd = s;
    fds[0].events = POLLIN;
    fds[1].fd = pcapfd;
    fds[1].events = POLLIN;
    for (i = 0; i < numcon; ++i) {
      fds[i + 2].fd = clients[i].d;
      fds[i + 2].events = POLLIN;
    }
    if (error > 0) {
      // TODO(willscott): Reset state.
      error = 0;
    }
    if (poll(fds, numcon + 2, 100)) {
      gettimeofday(&now, NULL);
      for (i = 0; i < numcon; ++i) {
        if ((clients[i].state == 4 && (unsigned long)now.tv_sec * 1000000 + now.tv_usec > clients[i].delay + 3000000) ||
            (clients[i].state == 0 && clients[i].traceid != NULL &&
             (unsigned long)now.tv_sec * 1000000 + now.tv_usec > clients[i].delay + 5000000)) {
          printf("Stats now\n");
          // Summary statistics
          if (clients[i].traceid != NULL) {
            send200(clients[i].d, (struct trace*)clients[i].traceid);
            cleanupTrace(clients[i].traceid);
          } else {
            send404(clients[i].d);
          }
          close(clients[i].d);
          for (j = i + 1; j < numcon; ++j) {
            clients[j - 1] = clients[j];
            fds[j] = fds[j + 1];
          }
          --numcon;
          --i;
        }
        /* Read from an existing client */
        if (fds[i + 2].revents != 0) {
          //printf("got client event\n");
          len = recv(clients[i].d, buf, sizeof(buf), 0);
          //Disconnect
          if (len <= 0) {
            close(clients[i].d);
            if (clients[i].traceid != NULL) {
              cleanupTrace(clients[i].traceid);
            }
            for (j = i + 1; j < numcon; ++j) {
              clients[j - 1] = clients[j];
              fds[j] = fds[j + 1];
            }
            --numcon;
            --i;
          } else {
            if (clients[i].state == 0) { // no data read yet.
              if (strncasecmp("GET / ", buf, 6) == 0) {
                clients[i].state = 1;
              } else if (strncasecmp("GET /result.json", buf, 16) == 0) {
                // Delay this request 1 second to give trace time to return.
                clients[i].state = 4;
                clients[i].delay = (unsigned long)now.tv_sec * 1000000 + now.tv_usec;
                printf("Stats in 1 second compared.\n");
              } else {
                send404(clients[i].d);
                close(clients[i].d);
                for (j = i + 1; j < numcon; ++j) {
                  clients[j - 1] = clients[j];
                  fds[j] = fds[j + 1];
                }
                if (clients[i].traceid != NULL) {
                  cleanupTrace(clients[i].traceid);
                }
                --numcon;
                --i;
              }
            }
            if (clients[i].state == 1) {
              if(strstr(buf, "\r\n\r\n") != 0) {
                clients[i].state = 0;
                clients[i].delay = (unsigned long)now.tv_sec * 1000000 + now.tv_usec;
                clients[i].data = (void*)get302();
                clients[i].left = strlen((char*)clients[i].data);
                printf("End of Input!\n");
                clients[i].traceid = beginTrace(clients[i].d, &clients[i].cin);
                clients[i].left -= send(clients[i].d, clients[i].data, clients[i].left, 0);
              } else if (strlen(buf) > 2 && strncmp(&buf[strlen(buf) - 2], "\r\n\r\n", 4) == 0) {
                clients[i].state = 2;
              }
            } else if (clients[i].state == 2 && strncmp(buf, "\r\n\r\n", 4) == 0) {
              clients[i].state = 0;
              clients[i].delay = (unsigned long)now.tv_sec * 1000000 + now.tv_usec;
              clients[i].data = (void*)get302();
              clients[i].left = strlen((char*)clients[i].data);
              printf("End of Input!\n");
              clients[i].traceid = beginTrace(clients[i].d, &clients[i].cin);
              clients[i].left -= send(clients[i].d, clients[i].data, clients[i].left, 0);
            } else if (clients[i].state == 2) {
              clients[i].state = 1;
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
          if (errno == EAGAIN) {
            continue;
          }
          perror("client accept failure");
          exit(1);
        }
        gettimeofday(&clients[numcon].start, NULL);
        printf("accepted\n");
        clients[numcon].state = 0;
        clients[numcon].traceid = NULL;
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
      if (fds[1].revents != 0) {
        processPcap();
      }
    }
  }

  /* Cleanup */
  return 0;
}

