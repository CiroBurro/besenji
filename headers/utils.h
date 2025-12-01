#pragma once

#include <net/if.h>
#define DIM_BUF 65535
#define SUCCESS 1
#define FAILURE -1

extern const char ipForwardFile[];

void usage();
void panic(const char *errMsg);

int ipForward();
int enablePromisc(struct ifreq *ifr, char *interface, int sockfd);

