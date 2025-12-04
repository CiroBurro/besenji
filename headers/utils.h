#pragma once

#include <net/if.h>

#define DIM_BUF 65535
#define SUCCESS 1
#define FAILURE -1

extern const char ipForwardFile[];
extern int sockfd;
extern struct ifreq ifr;

void usage();
void panic(const char *errMsg);

int ipForward(int value);
int enablePromisc(char *interface);
void disablePromisc();

char* mac_str(const unsigned char *mac_addr);

void dump(unsigned char *data_buffer, unsigned int length);

void sigHandler(int signum);
