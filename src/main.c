#include <sys/socket.h>
#include <netinet/in.h>

#include <net/if.h>
#include <linux/if_packet.h>

#include <string.h>
#include <signal.h>

#include "../headers/sniffer.h"
#include "../headers/utils.h"

int sockfd;
struct ifreq ifr;

int main(int argc, char *argv[])
{
	int ifIndex, len;
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

	if (ipForward(1) == FAILURE) {
		panic("Error in ipForward");
	}

	if ( (ifIndex = enablePromisc(interface)) == FAILURE ) {
		panic("Error in enablePromisc");
	}


	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifIndex;
	sll.sll_protocol = htons(ETH_P_ALL);

	if (bind(sockfd, (const struct sockaddr*) &sll, sizeof(sll)) == FAILURE) {
		panic("Error in bind");
	}

	signal(SIGTERM, sigHandler);
	signal(SIGINT, sigHandler);

	while (1) {
		len = recv(sockfd, buffer, sizeof(buffer), 0);

		handlePacket(buffer, len);
	}

	return 0;
}
