#include <linux/if_ether.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include "../headers/utils.h"

int main(int argc, char *argv[])
{
	int sockfd, ifIndex, len;
	struct ifreq ifr;
	struct sockaddr_ll sll;
	char interface[6], buffer[DIM_BUF];

	if (argc != 2){
		usage();
	}
	

	if (strlen(argv[1]) <= IFNAMSIZ) {
		strcpy(interface, argv[1]);
	}
	else {
		panic("Invalid interface");
	}
	
	if ( (sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == FAILURE ) {
		panic("Error in socket");
	}

	if (ipForward() == FAILURE) {
		panic("Error in ipForward");
	}

	if ( (ifIndex = enablePromisc(&ifr, interface, sockfd)) == FAILURE ) {
		panic("Error in enablePromisc");
	}


	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifIndex;
	sll.sll_protocol = htons(ETH_P_ALL);

	if (bind(sockfd, (const struct sockaddr*) &sll, sizeof(sll)) == FAILURE) {
		panic("Error in bind");
	}

	while (1) {
		len = recv(sockfd, buffer, sizeof(buffer), 0);

	}

	return 0;
}
