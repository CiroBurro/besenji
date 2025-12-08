#include <sys/socket.h>
#include <netinet/in.h>

#include <net/if.h>
#include <linux/if_packet.h>

#include <string.h>
#include <signal.h>

#include "../headers/sniffer.h"
#include "../headers/utils.h"

/*
 * main.c - besenji packet sniffer entry point
 *
 * This file contains the program entry point and the main capture loop. It:
 *  - parses the command line (expects a single interface name)
 *  - creates a raw AF_PACKET socket bound to the interface
 *  - enables IPv4 forwarding and promiscuous mode while running
 *  - installs signal handlers to restore system state on termination
 *  - receives raw frames and forwards them to the packet handler
 *
 * All comments and function descriptions are written in English.
 */

int sockfd;
struct ifreq ifr;

int main(int argc, char *argv[])
{
	int ifIndex, len;
	struct sockaddr_ll sll;
	char interface[IFNAMSIZ], buffer[DIM_BUF];
	

	if (argc != 2){
		usage();
	}
	

	if (strlen(argv[1]) <= IFNAMSIZ) {
		/* copy provided interface name into local buffer */
		strcpy(interface, argv[1]);
	}
	else {
		panic("Invalid interface");
	}
	
	/*
	 * Create a raw AF_PACKET socket to receive L2 Ethernet frames.
	 * The protocol ETH_P_ALL receives all Ethernet protocols.
	 */
	if ( (sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == FAILURE ) {
		panic("Error in socket");
	}

	/* Enable IPv4 forwarding temporarily while the program runs. */
	if (ipForward(1) == FAILURE) {
		panic("Error in ipForward");
	}

	/* Enable promiscuous mode on the requested interface. Returns the ifindex. */
	if ( (ifIndex = enablePromisc(interface)) == FAILURE ) {
		panic("Error in enablePromisc");
	}


	/* Bind the socket to the requested interface index so we only receive packets
	 * for that device. */
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifIndex;
	sll.sll_protocol = htons(ETH_P_ALL);

	if (bind(sockfd, (const struct sockaddr*) &sll, sizeof(sll)) == FAILURE) {
		panic("Error in bind");
	}

	/* Install signal handlers to clean up on SIGTERM / SIGINT */
	signal(SIGTERM, sigHandler);
	signal(SIGINT, sigHandler);

	/* Main packet receive loop: recv() returns raw frame bytes which are
	 * passed to handlePacket() for parsing and printing. */
	while (1) {
		len = recv(sockfd, buffer, sizeof(buffer), 0);

		handlePacket(buffer, len);
	}

	return 0;
}
