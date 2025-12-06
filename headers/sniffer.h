#pragma once

#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

void handlePacket(char* buf, unsigned int len);

int parseEth(const struct ethhdr *ethHdr);
int parseIp(const struct iphdr *ipHdr);
void parseTcp(const struct tcphdr *tcpHdr);
void parseUdp(const struct udphdr *udpHdr);
