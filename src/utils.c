#include <net/if.h>
#include <sys/ioctl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../headers/utils.h"

/*
 * utils.c - helper routines
 *
 * This module provides small utility functions used by the sniffer:
 *  - usage / panic: simple program messaging and exit
 *  - ipForward: temporarily enable/disable IPv4 forwarding via /proc
 *  - enablePromisc / disablePromisc: toggle interface promiscuous mode
 *  - mac_str: human-readable MAC address formatting
 *  - dump: hex + ASCII payload dump
 *  - sigHandler: signal handler to restore system state on exit
 */

const char ipForwardFile[] = "/proc/sys/net/ipv4/ip_forward";

void usage() {
	printf("Usage:\n\tbesenji [interface]\n\nInterfaces:\n\t- Any valid interface (eth0, wlan0, ...)\n");

	exit(FAILURE);
}

void panic(const char *errMsg) {
	printf("%s\n", errMsg);
	exit(FAILURE);
}

/*
 * ipForward - write '1' or '0' to /proc/sys/net/ipv4/ip_forward
 * Returns SUCCESS on success or FAILURE on error.
 */
int ipForward(const int value) {
	FILE *fp;
	int result = SUCCESS;
	char c = ' ';

	switch (value) {
		case 0: c = '0'; break;
		case 1: c = '1'; break;
		default: panic("Invalid value for ip forwarding");
	}

	if ( (fp = fopen(ipForwardFile, "w")) == NULL ) {
		result = FAILURE;
	}
	else {
		if (fprintf(fp, "%c", c) != 1) {
			result = FAILURE;
		};

		fclose(fp);
	}

	return result;
}

/*
 * enablePromisc - enable promiscuous mode on a named interface
 * Returns the interface index (>0) on success or FAILURE on error.
 * Note: this function uses the global 'ifr' and the global 'sockfd'.
 */
int enablePromisc(const char *interface) {
	int index;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_ifrn.ifrn_name, interface, IFNAMSIZ);

	if ( (index = ioctl(sockfd, SIOCGIFINDEX, &ifr)) != FAILURE ) {

		ioctl(sockfd, SIOCGIFFLAGS, &ifr);
		ifr.ifr_ifru.ifru_flags |= IFF_PROMISC;
		ioctl(sockfd, SIOCSIFFLAGS, &ifr);
	}

	return index;

}

/*
 * disablePromisc - clear promiscuous bit on the previously used interface
 */
void disablePromisc() {
	ioctl(sockfd, SIOCGIFFLAGS, &ifr);
	ifr.ifr_ifru.ifru_flags &= ~IFF_PROMISC;
	ioctl(sockfd, SIOCSIFFLAGS, &ifr);
}


/*
 * mac_str - format a 6-byte MAC address into a static string buffer
 * The returned pointer points to a static buffer (overwritten on each call).
 */
const char* mac_str(const unsigned char *mac_addr) {
	static char buf_mac[18];

	snprintf(buf_mac, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac_addr[0], mac_addr[1], mac_addr[2], 
             mac_addr[3], mac_addr[4], mac_addr[5]);

	return buf_mac;
}

/*
 * dump - print a hex + ASCII dump of 'length' bytes from data_buffer
 * Each line contains up to 16 bytes with a delimiter between hex and ASCII.
 */
void dump(const unsigned char *data_buffer, const unsigned int length) {
	unsigned char byte;
	unsigned int i, j;

	for(i=0; i < length; i++) {
		
		byte = data_buffer[i];
		printf("%02x ", data_buffer[i]);
		
		if(((i%16)==15) || (i==length-1)) {

			for(j=0; j < 15-(i%16); j++) {
				printf("   ");
			}

			printf("| ");

			for(j=(i-(i%16)); j <= i; j++) { 
				
				byte = data_buffer[j];
				
				if((byte > 31) && (byte < 127))
					printf("%c", byte);
				else
					printf(".");
			}

			printf("\n");
		}
	}
}

/*
 * sigHandler - restore ip forwarding and disable promiscuous mode then exit
 */
void sigHandler(int signum) {
	
	if (ipForward(0) == FAILURE) {
		panic("Error in ipForward");
	}
	disablePromisc();

	exit(0);
}
