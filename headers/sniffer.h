#pragma once

#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

int handlePacket(char *buf, int len);

int parseEth(struct ethhdr *ethHdr);
int parseIp(struct iphdr *ipHdr);
void parseTcp(struct tcphdr *tcpHdr);
void parseUdp(struct udphdr *udpHdr);
