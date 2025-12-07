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

int parseEth(const struct ethhdr *ethHdr) {
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

int parseIp(const struct iphdr *ipHdr) {
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

void parseTcp(const struct tcphdr *tcpHdr) {
	
	printf("[L4: TCP]\n  Source port:\t%hu\n  Dest port:\t%hu\n  Seq:\t%u\n  Ack:\t%u\n Flags: ", ntohs(tcpHdr->source), ntohs(tcpHdr->dest), ntohl(tcpHdr->seq), ntohl(tcpHdr->ack_seq));

	if (tcpHdr->syn) {
		printf("SYN ");
	}
	if (tcpHdr->ack) {
    printf("ACK ");
	}
	if (tcpHdr->fin) {
    printf("FIN ");
	}
	if (tcpHdr->rst) {
    printf("RST ");
	}
	if (tcpHdr->psh) {
    printf("PSH ");
	}
	if (tcpHdr->urg) {
    printf("URG ");
	}
	printf("\n\n");

}

void parseUdp(const struct udphdr *udpHdr) {

	printf("[L4: UDP]\n  Source port:\t%hu\n  Dest port:\t%hu\n\n", ntohs(udpHdr->source), ntohs(udpHdr->dest));

}


void handlePacket(const char* buf, unsigned int len) {
	struct ethhdr *ethHdr;
	struct iphdr *ipHdr;
	struct tcphdr *tcpHdr;
	struct udphdr *udpHdr;
	int isIp, ipProt;
	unsigned dataLen;

	printf("\n\n--- Captured Packet (%d bytes) ---\n", len);

	if (len < sizeof(struct ethhdr)) {
		return;
	}

	ethHdr = (struct ethhdr*) buf;
	isIp = parseEth(ethHdr);

	if (isIp) {
		
		if (len < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
			printf("Packet too small for IP header\n");
			return;
		}
	
		ipHdr = (struct iphdr*) (buf + sizeof(struct ethhdr));
		ipProt = parseIp(ipHdr);

		if (ipProt == IPPROTO_TCP) {
			tcpHdr = (struct tcphdr*) (buf + sizeof(struct ethhdr) + ipHdr->ihl * 4);
			parseTcp(tcpHdr);

			dataLen = len - sizeof(struct ethhdr) - (ipHdr->ihl * 4) - (tcpHdr->doff * 4);

			if (dataLen > 0) {
				printf("%u bytes of packet data\n", dataLen);
				dump((const unsigned char*)(buf + len - dataLen), dataLen);
			}
			else {
				printf("No Packet Data\n\n");
			}

		}
		else if (ipProt == IPPROTO_UDP) {

			udpHdr = (struct udphdr*) (buf + sizeof(struct ethhdr) + ipHdr->ihl * 4);
			parseUdp(udpHdr);

			dataLen = len - sizeof(struct ethhdr) - (ipHdr->ihl * 4) - sizeof(struct udphdr);

			if (dataLen > 0) {
				printf("%u bytes of packet data\n", dataLen);
				dump((const unsigned char*)(buf + len - dataLen), dataLen);
			}
			else {
				printf("No Packet Data\n\n");
			}

		}

	}

}

