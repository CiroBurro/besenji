#pragma once

#include <linux/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

/*
 * sniffer.h - public API for packet parsing and handling
 *
 * All functions are documented here. Comments are written in English.
 */

/*
 * handlePacket - top-level packet processor
 *  - buf: pointer to raw bytes received from an AF_PACKET socket
 *  - len: number of valid bytes in buf
 * Behavior: parses Ethernet / IP / TCP / UDP headers if present and prints
 *           human-readable information and a payload dump to stdout.
 */
void handlePacket(const char* buf, unsigned int len);

/* Ethernet, IP, and transport header parsers. Return or print useful data:
 *  - parseEth: returns 1 if the Ethernet payload is IPv4, 0 otherwise
 *  - parseIp: returns the IP protocol number (e.g., IPPROTO_TCP), prints info
 *  - parseTcp / parseUdp: print L4 header information
 */
int parseEth(const struct ethhdr *ethHdr);
int parseIp(const struct iphdr *ipHdr);
void parseTcp(const struct tcphdr *tcpHdr);
void parseUdp(const struct udphdr *udpHdr);
