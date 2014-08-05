void initSender();
void craftPkt(unsigned int to, unsigned int from, struct tcphdr* req, unsigned short reqlen, unsigned char ttl);
