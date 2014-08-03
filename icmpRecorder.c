#include <stdlib.h>
#include "icmpRecorder.h"
#include "tcpServer.h"
#include "tcpSender.h"

pcap_t *handle;
unsigned int sendingAddress;
struct trace* activeTraces[MAX_CONNECTIONS];
size_t activeTraceCount = 0;
struct seqreq seqnums[100];
size_t seqnumpos = 0;

int beginCapture() {
  char* dev, errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevsp, *devsp;
  //TODO(willscott): Remove IPv4 Limitation
  bpf_u_int32 mask;
  bpf_u_int32 net;

  struct bpf_program fp;
  char filter_exp[] = "icmp[icmptype] == icmp-timxceed or (tcp port 8080)";

  // Find Device.
  if (pcap_findalldevs(&alldevsp, errbuf)) {
    printf("Couldn't find Devices: %s \n", errbuf);
    exit(1);
  }
  devsp = alldevsp;
  dev = NULL;
  while (devsp != NULL) {
    // flags = !loopback
    if (devsp->addresses != NULL && (devsp->flags & 1) != 1) {
      dev = devsp->name;
      break;
    } else {
      devsp = devsp->next;
    }
  }
  if (dev == NULL) {
    printf("No valid device found!\n");
    exit(1);
  }
  printf("Using Dev %s\n", dev);

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

  // free list
  pcap_freealldevs(alldevsp);

  // Set the filter.
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    printf("Invalid Filter: %s\n", filter_exp);
    exit(1);
  }
  if (pcap_setfilter(handle, &fp) == -1) {
    printf("Filter couldn't be installed: %s\n", pcap_geterr(handle));
    exit(1);
  }

  if (pcap_setnonblock(handle, 1, errbuf) == -1) {
    printf("Nonblocking mode failed: %s\n", errbuf);
    exit(1);
  }

  // Initialize Sending.
  initSender();

  return pcap_get_selectable_fd(handle);
};

void processPcap() {
  int packet_count = 0;
  int ret = pcap_dispatch(handle, -1, handlePcap, (u_char *)&packet_count);
  if (ret < 0) {
    pcap_perror(handle, "pcap");
  }
  printf("%d packets seen, %d packets counted after select returns\n",
  				    ret, packet_count);
}

void handlePcap(u_char *user, const struct pcap_pkthdr * header, const u_char *bytes) {
  struct pktinfo *packet;
  int i;
  unsigned short hop;
  // TODO: should multiple packets be handled?
  packet = (struct pktinfo*)bytes;
  printf("got packet.\n");
  if (header->caplen >= 66 && packet->iphdr.ip_p == 1) {
    // Enough to have tcp header through checksum:
    // 20 ip + 8 icmp + 20 ip + 18 (of 20+) tcp
    if (packet->eiphdr.ip_v == 4 && packet->eiphdr.ip_p == 6) {
      // Original packet should have been ipv4 tcp.
      for (i = 0; i < activeTraceCount; i++) {
        if (activeTraces[i]->to == packet->eiphdr.ip_dst.s_addr) {
          printf("got relevant traced packet.\n");
          // Part of active trace.
          hop = activeTraces[i]->recordedHops;
          activeTraces[i]->hops[hop].ip = packet->iphdr.ip_src.s_addr;
          activeTraces[i]->hops[hop].ttl = packet->eiphdr.ip_ttl;
          activeTraces[i]->hops[hop].len = header->len;
          activeTraces[i]->recordedHops += 1;
          break;
        }
      }
    }
  } else if (header->caplen >= 33 && packet->iphdr.ip_p == 6) {
    // Log
    seqnums[seqnumpos].to = packet->iphdr.ip_dst.s_addr;
    seqnums[seqnumpos].seq = ((unsigned int*)packet)[9] + packet->iphdr.ip_len -\
        ((((char*)packet)[32] & 0xf0)>>2);
    struct in_addr des;
    des.s_addr = packet->iphdr.ip_dst.s_addr;
    printf("seq recovered %s -> %d\n", inet_ntoa(des), seqnums[seqnumpos].seq);
    seqnumpos += 1;
    seqnumpos %= 100;
  } else {
    printf("ignoring packet with caplen %d, proto %d\n", header->caplen, packet->iphdr.ip_p);
  }
};

void* beginTrace(int d, struct sockaddr_in* to) {
  struct sockaddr_in local;
  int i, m, seq;
  struct trace* tr = (struct trace*)malloc(sizeof(struct trace));
  tr->to = to->sin_addr.s_addr;
  tr->recordedHops = 0;
  activeTraces[activeTraceCount] = tr;
  activeTraceCount += 1;

  // Get local address if needed.
  if (!sendingAddress) {
    i = sizeof(local);
    getsockname(d, (struct sockaddr*)&local, (socklen_t *)&i);
    sendingAddress = local.sin_addr.s_addr;
  }

  // Send the probes.
  seq = 0;
  for (m = 0; m < 100; m++) {
    i = (seqnumpos - m - 1) % 100;
    if (seqnums[i].to == tr->to) {
      seq = seqnums[i].seq;
      printf("Sequence Number recovered: %d\n", seq);
      break;
    }
  }
  if (seq == 0) {
    cleanupTrace(tr);
    return 0;
  }

  for (i = 0; i < MAX_HOPS; i++) {
    craftPkt(tr->to, to->sin_port, sendingAddress, seq, i);
  }

  return tr;
};

struct hop* showTrace(void* id) {
  struct trace* r = (struct trace*)id;
  return r->hops;
};

void cleanupTrace(void* id) {
  size_t i;
  for (i = activeTraceCount - 1; i > 0; i--) {
    if (activeTraces[i] == id) {
      break;
    }
  }
  activeTraces[i] = activeTraces[activeTraceCount - 1];
  activeTraceCount -= 1;
  free(id);
};
