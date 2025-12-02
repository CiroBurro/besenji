#include <linux/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <arpa/inet.h>

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include "../headers/sniffer.h"
#include "../headers/utils.h"

int parseEth(struct ethhdr *ethHdr) {
	uint16_t protocol;
	char protName[6];
	int isIp = 0;

	protocol = ntohs(ethHdr->h_proto);

	switch (protocol) {
		case ETH_P_IP: strcpy(protName, "IPv4"); isIp = 1; break;
		case ETH_P_IPV6: strcpy(protName, "IPv6"); break; 
		case ETH_P_ARP: strcpy(protName, "ARP"); break; 
		case ETH_P_RARP: strcpy(protName, "RARP"); break; 
		case ETH_P_LLDP: strcpy(protName, "LLDP"); break; 
		default: strcpy(protName, "OTHER"); break;
	}

	printf("[L2: ETHERNET]\n  MAC source:\t%s\n  MAC dest:\t%s\n  Protocol type:\t%d (%s)\n\n", mac_str(ethHdr->h_source), mac_str(ethHdr->h_dest), protocol, protName);

	return isIp;
}

int parseIp(struct iphdr *ipHdr) {
	uint8_t protocol;
	char protName[10], srcIp[INET_ADDRSTRLEN], destIp[INET_ADDRSTRLEN];

	protocol = ipHdr->protocol;
	if (inet_ntop(AF_INET, &ipHdr->saddr, srcIp, INET_ADDRSTRLEN) == NULL) {
		panic("In inet_ntop (src)");
	}
	if (inet_ntop(AF_INET, &ipHdr->daddr, destIp, INET_ADDRSTRLEN) == NULL) {
		panic("In inet_ntop (dest)");
	}

	switch (protocol) {
		case IPPROTO_TCP: strcpy(protName, "TCP"); break;
		case IPPROTO_UDP: strcpy(protName, "UDP"); break;
		default: strcpy(protName, "OTHER"); break;
	}

	printf("[L3: IPV4]\n  IP source:\t%s\n  IP dest:\t%s\n  TTL:\t%d\n  Protocol:\t%d (%s)\n\n", srcIp, destIp, ipHdr->ttl, protocol, protName);

	return protocol;
}
void parseTcp(struct tcphdr *tcpHdr) {

}

int handlePacket(char *buf, int len) {
	struct ethhdr *ethHdr;
	struct iphdr *ipHdr;
	struct tcphdr *tcpHdr;
	struct udphdr *udpHdr;
	int isIp, ipProt;

	printf("--- Captured Packet (%d bytes) ---\n", len);

	if (len < sizeof(struct ethhdr)) {
		return SUCCESS;
	}

	ethHdr = (struct ethhdr*) buf;
	isIp = parseEth(ethHdr);

	if (isIp) {
		
		if (len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
			printf("Packet too small for IP header\n");
			return SUCCESS;
		}
	
		ipHdr = (struct iphdr*) (buf + sizeof(struct ethhdr));
		ipProt = parseIp(ipHdr);
	}


	return SUCCESS;
}

