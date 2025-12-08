#pragma once

#include <net/if.h>

#define DIM_BUF 65535
#define SUCCESS 1
#define FAILURE (-1)

/*
 * utils.h - helper utilities shared between modules
 *
 * Provides small helpers for printing, ip forwarding, promisc mode and
 * payload dumping. All comments and documentation are in English.
 */

extern const char ipForwardFile[];
extern int sockfd;
extern struct ifreq ifr;

/* Program messaging and error helpers */
void usage();
void panic(const char *errMsg);

/* ip forwarding helpers: 1 to enable, 0 to disable; return SUCCESS/FAILURE */
int ipForward(int value);

/* Enable/disable promiscuous mode on a named interface. Returns ifindex or FAILURE. */
int enablePromisc(const char *interface);
void disablePromisc();

/* Format and dump helpers */
const char* mac_str(const unsigned char *mac_addr);
void dump(const unsigned char *data_buffer, unsigned int length);

/* Signal handler used to restore state and exit */
void sigHandler(int signum);
