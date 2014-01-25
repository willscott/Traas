#include <pcap.h>
#include <stdlib.h>
#include "icmpRecorder.h"

pcap_t *handle;

int beginCapture() {
  char* dev, errbuf[PCAP_ERRBUF_SIZE];
  //TODO(willscott): Remove IPv4 Limitation
  bpf_u_int32 mask;
  bpf_u_int32 net;

  struct bpf_program fp;
  char filter_exp[] = "icmp[icmptype] == icmp-timxceed";

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

  // Set the filter.
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    printf("Invalid Filter: %s\n", filter_exp);
    exit(1);
  }
  if (pcap_setfilter(handle, &fp) == -1) {
    printf("Filter couldn't be installed: %s\n", pcap_geterr(handle));
    exit(1);
  }

  return pcap_get_selectable_fd(handle);
};

void processPcap() {
  struct pcap_pkthdr header;
  const u_char *packet;
  // TODO: should multiple packets be handled?
  packet = pcap_next(handle, &header);
  printf("Jacked a packet with length of [%d]\n", header.len);
};

char* beginTrace(struct sockaddr_in* to) {
};

struct hop* infoFor(char* id) {
};
