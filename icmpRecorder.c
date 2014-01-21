#include <pcap.h>
#include <stdlib.h>
#include "icmpRecorder.h"

pcap_t *handle;

void beginCapture() {
  char* dev, errbuf[PCAP_ERRBUF_SIZE];
  //TODO(willscott): Remove IPv4 Limitation
  bpf_u_int32 mask;
  bpf_u_int32 net;

  // Find Device.
  dev = pcap_lookupdev(errbuf);
  if (dev == NULL) {
    printf("No valid device found! %s \n", errbuf);
    exit(1);
  }

  // Get Local IP.
  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
    printf("Couldn't get netmask for device %s: %s\n", dev, errbuf);
    exit(1);
  }

  // Open Device.
  handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    printf("Couldn't open device %s: %s\n", dev, errbuf);
    exit(1);
  }  
};

char* beginTrace(struct sockaddr_in* to) {
};

struct hop* infoFor(char* id) {
};
