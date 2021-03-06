#include <stdlib.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include "icmpRecorder.h"
#include "tcpServer.h"
#include "tcpSender.h"
#include "httpFormatter.h"

pcap_t *handle;
unsigned int sendingAddress;
struct trace* activeTraces[MAX_CONNECTIONS];
size_t activeTraceCount = 0;
char logbuffer[4096];
FILE* logfile;

int beginCapture() {
  char* dev, errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *alldevsp, *devsp;
  //TODO(willscott): Remove IPv4 Limitation
  bpf_u_int32 mask;
  bpf_u_int32 net;

  struct bpf_program fp;
  char filter_exp[] = "icmp[0:1] == 0x0b or (dst port 8080 and dst host %s)";
  char filterbuf[256];

  // Find Device. Gets the first valid device.
  if (pcap_findalldevs(&alldevsp, errbuf)) {
    printf("Couldn't find Devices: %s \n", errbuf);
    exit(1);
  }
  devsp = alldevsp;
  dev = NULL;
  while (devsp != NULL) {
    // flags = !loopback
    char* addr = NULL;
    if (devsp->addresses != NULL && (devsp->flags & 1) != 1) {
      struct pcap_addr* addrs = devsp->addresses;
      while (addrs != NULL) {
        if (addrs->addr->sa_family == AF_INET) {
          addr = inet_ntoa(((struct sockaddr_in*)addrs->addr)->sin_addr);
          break;
        }
        addrs = addrs->next;
      }
      if (addr != NULL) {
        sprintf(filterbuf, filter_exp,addr);
        printf("%s\n", filterbuf);
        dev = devsp->name;
        break;
      }
    } else {
      devsp = devsp->next;
    }
  }
  if (dev == NULL) {
    printf("No valid device found!\n");
    exit(1);
  }
  printf("Using Dev %s\n", dev);

  // Initialize Log.
  logfile = fopen("log.txt", "a");
  if (logfile == NULL) {
    printf("Couldn't open log file.\n");
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

  // free list
  pcap_freealldevs(alldevsp);

  // Set the filter.
  if (pcap_compile(handle, &fp, filterbuf, 0, net) == -1) {
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
}

void handlePcap(u_char *user, const struct pcap_pkthdr * header, const u_char *bytes) {
  int linkhdrlen = 14;
  struct ip* iphdr, *responsehdr;
  struct tcphdr* tcphdr;
  struct icmp* icmphdr;

  int icmpLength = linkhdrlen + sizeof(struct ip) + 4 + sizeof(struct ip);

  int i, j;
  unsigned short hop;
  unsigned short reqlen;

  // Make sure it's a valid IP header.
  iphdr = (struct ip*)(bytes + linkhdrlen);
  if (iphdr->ip_hl != 5 || iphdr->ip_v != 4) {
    return;
  }

  if (header->caplen >= icmpLength && iphdr->ip_p == 1) {
    // Enough to have tcp header through checksum:
    // 14ether + 20 ip + 8 icmp + 20 ip + 18 (of 20+) tcp
    i = iphdr->ip_hl << 2;
    icmphdr = (struct icmp*)(bytes + linkhdrlen + i);
    responsehdr = (struct ip*)((char*)icmphdr + 8);
    if (header->caplen < linkhdrlen + i + 8 + 20) {
      // packet truncates inner header.
      printf("ignoring truncated icmp response (being cautious).\n");
      return;
    } else if (responsehdr->ip_v == 4 && responsehdr->ip_p == 6) {
      // Original packet should have been ipv4 tcp.
      for (i = 0; i < activeTraceCount; i++) {
        if (activeTraces[i]->to == responsehdr->ip_dst.s_addr) {
          printf("got relevant traced packet.\n");
          // Part of active trace.
          hop = activeTraces[i]->recordedHops;
          activeTraces[i]->hops[hop].ip = iphdr->ip_src.s_addr;
          activeTraces[i]->hops[hop].ttl = iphdr->ip_ttl;
          activeTraces[i]->hops[hop].len = header->len;
          activeTraces[i]->recordedHops += 1;
          break;
        }
      }
    }
  } else if (header->caplen >= linkhdrlen + (iphdr->ip_hl << 2) + sizeof(struct tcphdr) && iphdr->ip_p == 6) {
    tcphdr = (struct tcphdr*)(bytes + linkhdrlen + (iphdr->ip_hl << 2));
    // see if this is for an active trace.

    for (i = 0; i < activeTraceCount; i++) {
      if (activeTraces[i]->to == iphdr->ip_src.s_addr && (tcphdr->th_flags & (TH_ACK | TH_SYN)) == TH_ACK &&
          activeTraces[i]->sent == 0 && ntohs(iphdr->ip_len) > 100) {
        reqlen = ntohs(iphdr->ip_len) - (iphdr->ip_hl << 2) - (tcphdr->th_off << 2);
        // Latched on to active request.
        printf("Recovered %s:%d -> [len:%d, seq:%d]\n", inet_ntoa(iphdr->ip_src),
               ntohs(tcphdr->th_sport), ntohs(iphdr->ip_len), tcphdr->th_ack);
        for (j = 1; j < MAX_HOPS; j++) {
          craftPkt(activeTraces[i]->to, sendingAddress, tcphdr, reqlen, j);
        }
        activeTraces[i]->sent = 1;
      }
    }
  }
};

void* beginTrace(int d, struct sockaddr_in* to) {
  struct sockaddr_in local;
  int i, m, seq;
  struct trace* tr = (struct trace*)malloc(sizeof(struct trace));
  tr->to = to->sin_addr.s_addr;
  tr->sent = 0;
  tr->recordedHops = 0;
  activeTraces[activeTraceCount] = tr;
  activeTraceCount += 1;

  // Get local address if needed.
  if (!sendingAddress) {
    i = sizeof(local);
    getsockname(d, (struct sockaddr*)&local, (socklen_t *)&i);
    sendingAddress = local.sin_addr.s_addr;
  }

  return tr;
};



void cleanupTrace(void* id) {
  if (id == NULL || activeTraceCount == 0) {
    return;
  }
  size_t i;
  printf("Cleanup called.\n");
  for (i = activeTraceCount - 1; i >= 0; i--) {
    if (activeTraces[i] == id) {
      printf("Cleanup found item to free\n");
      if (activeTraces[i]->sent > 0 && activeTraces[i]->recordedHops > 0) {
        printf("writing to log.\n");
        getjson(logbuffer, id);
        fprintf(logfile, "%s", logbuffer);
      }
      activeTraces[i] = activeTraces[activeTraceCount - 1];
      activeTraceCount -= 1;
      free(id);
      break;
    }
  }

};
