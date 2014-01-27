#include <pcap.h>
#include <stdlib.h>
#include "icmpRecorder.h"
#include "tcpServer.h"

pcap_t *handle;
struct trace* activeTraces[MAX_CONNECTIONS];
size_t activeTraceCount = 0;
struct seqreq seqnums[100];
size_t seqnumpos = 0;

int beginCapture() {
  char* dev, errbuf[PCAP_ERRBUF_SIZE];
  //TODO(willscott): Remove IPv4 Limitation
  bpf_u_int32 mask;
  bpf_u_int32 net;

  struct bpf_program fp;
  char filter_exp[] = "icmp[icmptype] == icmp-timxceed or (tcp port 80 and src host localhost)";

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
  struct pktinfo *packet;
  int i;
  unsigned short hop;
  // TODO: should multiple packets be handled?
  packet = (struct pktinfo*)pcap_next(handle, &header);
  if (header.caplen >= 66 && packet->proto == 1) {
    // Enough to have tcp header through checksum:
    // 20 ip + 8 icmp + 20 ip + 18 (of 20+) tcp
    if (packet->e_version == 4 && packet->e_proto == 6) {
      // Original packet should have been ipv4 tcp.
      for (i = 0; i < activeTraceCount; i++) {
        if (activeTraces[i]->to == packet->e_dest) {
          // Part of active trace.
          hop = activeTraces[i]->recordedHops;
          activeTraces[i]->hops[hop].ip = packet->source;
          activeTraces[i]->hops[hop].ttl = packet->e_ttl;
          activeTraces[i]->hops[hop].len = header.len;
          activeTraces[i]->recordedHops += 1;
          break;
        }
      }
    }
  } else if (header.caplen >= 33 && packet->proto == 6) {
    // Log
    seqnums[seqnumpos].to = packet->dest;
    seqnums[seqnumpos].seq = ((unsigned int*)packet)[9] + packet->length -\
        ((((char*)packet)[32] & 0xf0)>>2);
    seqnumpos += 1;
    seqnumpos %= 100;
  }
};

void* beginTrace(struct sockaddr_in* to) {
  int i, m, seq;
  struct trace* tr = (struct trace*)malloc(sizeof(struct trace));
  tr->to = to->sin_addr.s_addr;
  tr->recordedHops = 0;
  activeTraces[activeTraceCount];
  activeTraceCount += 1;

  // Send the probes.
  for (m = 0; m < 100; m++) {
    i = (seqnumpos - m - 1) % 100;
    if (seqnums[i].to == tr->to) {
      seq = seqnums[i].seq;
      break;
    }
  }
  if (seq == 0) {
    cleanupTrace(tr);
    return 0;
  }

  for (i = 0; i < MAX_HOPS; i++) {
    craftPkt(tr->to, seq);
  }

  return tr;
};

struct hop* showTrace(void* id) {
  struct trace* r = (struct trace*)id;
  return r->hops;
};

void cleanupTrace(void* id) {
  size_t i;
  for (i = activeTraceCount - 1; i >= 0; i--) {
    if (activeTraces[i] == id) {
      break;
    }
  }
  activeTraces[i] = activeTraces[activeTraceCount - 1];
  activeTraceCount -= 1;
  free(id);
};

void craftPkt(unsigned int to, unsigned int seq) {
};
