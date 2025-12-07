Besenji
=======

Overview
--------
Besenji is a small packet sniffer written in C for Linux that captures raw Ethernet frames on a network interface, parses Ethernet, IPv4, TCP and UDP headers, and prints human-readable summaries and hex/ascii dumps of packet payloads. It uses Linux raw AF_PACKET sockets and operates at L2 so it does not rely on libpcap.

Key features
------------
- Capture raw Ethernet frames from a network interface
- Parse and display Ethernet, IPv4, TCP and UDP headers
- Hex + ASCII dump of packet payloads
- Enables promiscuous mode and temporarily enables IPv4 forwarding while running
- Restores settings on SIGINT / SIGTERM

Repository layout
-----------------
- src/
  - main.c        — program entry point, socket setup, main recv loop
  - sniffer.c     — packet parsing and formatting logic
  - utils.c       — helper routines (usage, ip forwarding, promisc, dump, signal handler)
- headers/
  - sniffer.h
  - utils.h
- CMakeLists.txt  — CMake configuration for building besenji

Requirements
------------
- Linux (code uses Linux-specific headers like <linux/if_packet.h> and <linux/if_ether.h>)
- Root privileges or the CAP_NET_RAW / CAP_NET_ADMIN capability to create raw sockets and change interface flags

Run
---
You must run the program with sufficient privileges. Either run as root or give the executable the necessary capabilities.

Example (run as root):

```bash
sudo ./besenji eth0
```

Or grant capabilities (safer than running as root):

```bash
sudo setcap cap_net_raw,cap_net_admin+ep ./besenji
./build/besenji eth0
```

Usage
-----
```
besenji [interface]

Examples:
  besenji eth0
  besenji wlan0
```

What it does at runtime
-----------------------
- Opens a raw `AF_PACKET` socket bound to the requested interface
- Enables IPv4 forwarding by writing to `/proc/sys/net/ipv4/ip_forward` (writes `1` on start, `0` on exit)
- Enables promiscuous mode on the interface
- Receives packets in a loop and prints parsed header information and a hex+ASCII dump of payload data
- On SIGINT/SIGTERM it tries to restore IPv4 forwarding and disable promiscuous mode

Dependencies and privileges
---------------------------
- No external libraries required (no libpcap). The program uses standard libc and Linux kernel headers.
- Requires root privileges or the correct Linux capabilities to open raw sockets and change interface flags.