#include <net/if.h>
#include <sys/ioctl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../headers/utils.h"

const char ipForwardFile[] = "/proc/sys/net/ipv4/ip_forward";

void usage() {
	printf("Usage:\n\tbesenji [interface]\n\nInterfaces:\n\t- Any valid interface (eth0, wlan0, ...)\n");

	exit(FAILURE);
}

void panic(const char *errMsg) {
	printf("%s\n", errMsg);
	exit(FAILURE);
}

int ipForward() {
	FILE *fp;
	int result = SUCCESS;

	if ( (fp = fopen(ipForwardFile, "w")) == NULL ) {
		result = FAILURE;
	}
	else {
		if (fprintf(fp, "1") != 1) {
			result = FAILURE;
		};
	}

	fclose(fp);
	return result;
}

int enablePromisc(struct ifreq *ifr, char *interface, int sockfd) {
	int index;
	memset(ifr, 0, sizeof(*ifr));
	strncpy(ifr->ifr_ifrn.ifrn_name, interface, IFNAMSIZ);

	if ( (index = ioctl(sockfd, SIOCGIFINDEX, ifr)) != FAILURE ) {

		ioctl(sockfd, SIOCGIFFLAGS, ifr);
		ifr->ifr_ifru.ifru_flags |= IFF_PROMISC;
		ioctl(sockfd, SIOCSIFFLAGS, ifr);
	}

	return index;

}


char* mac_str(const unsigned char *mac_addr) {
	static char buf_mac[18];

	snprintf(buf_mac, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac_addr[0], mac_addr[1], mac_addr[2], 
             mac_addr[3], mac_addr[4], mac_addr[5]);

	return buf_mac;
}

