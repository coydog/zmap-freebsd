/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "send.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include <arpa/inet.h>
#ifdef __FREEBSD_INCLUDES__
	#include <pcap/pcap.h> /* TODO:other BSD's*/
	#include <sys/types.h>
	#include <sys/socket.h>
	#include <ifaddrs.h>
	#include <net/if_dl.h> /* for sockaddr_dl */
	/* beware, defined in other modulkes */
	#define PCAP_PROMISC 1
	#define PCAP_TIMEOUT 1000
#else /* TODO double check this */
	#include <sys/socket.h> 
	#include <sys/ioctl.h>
#endif
#include <net/if.h>

/* might want to change to ifdef __LINUX__. Will help more than just FreeBSD */
#ifdef __FREEBSD_INCLUDES__
#include "proto_headers.h"
#else
#include <linux/if_packet.h>
#endif /* __FREEBSD__ */

#include "../lib/logger.h"
#include "../lib/random.h"
#include "../lib/blacklist.h"

#include "cyclic.h"
#include "state.h"
#include "probe_modules/packet.h"
#include "probe_modules/probe_modules.h"
#include "validate.h"


// lock to manage access to share send state (e.g. counters and cyclic)
pthread_mutex_t send_mutex = PTHREAD_MUTEX_INITIALIZER;
// lock to provide thread safety to the user provided send callback
pthread_mutex_t syncb_mutex = PTHREAD_MUTEX_INITIALIZER;

// globals to handle sending from multiple ip addresses (shared across threads)
static uint16_t num_src_ports;
static uint32_t num_addrs;
static in_addr_t srcip_first;
static in_addr_t srcip_last;
// offset send addresses according to a random chosen per scan execution
// in order to help prevent cross-scan interference
static uint32_t srcip_offset;

// global sender initialize (not thread specific)
int send_init(void)
{
	// generate a new primitive root and starting position
	cyclic_init(0, 0);
	zsend.first_scanned = cyclic_get_curr_ip();

	// compute number of targets
	uint64_t allowed = blacklist_count_allowed();
	if (allowed == (1LL << 32)) {
		zsend.targets = 0xFFFFFFFF;
	} else {
		zsend.targets = allowed;
	}
	if (zsend.targets > zconf.max_targets) {
		zsend.targets = zconf.max_targets;
	}

	// process the dotted-notation addresses passed to ZMAP and determine
	// the source addresses from which we'll send packets;
	srcip_first = inet_addr(zconf.source_ip_first);
	if (srcip_first == INADDR_NONE) {
		log_fatal("send", "invalid begin source ip address: `%s'",
				zconf.source_ip_first);
	}
	srcip_last = inet_addr(zconf.source_ip_last);
	if (srcip_last == INADDR_NONE) {
		log_fatal("send", "invalid end source ip address: `%s'",
				zconf.source_ip_last);
	}
	if (srcip_first == srcip_last) {
		srcip_offset = 0;
		num_addrs = 1;
	} else {
		srcip_offset = rand() % (srcip_last - srcip_first);
		num_addrs = ntohl(srcip_last) - ntohl(srcip_first) + 1;
	}

	// process the source port range that ZMap is allowed to use
	num_src_ports = zconf.source_port_last - zconf.source_port_first + 1;
	log_debug("send", "will send from %i address%s on %u source ports",
		 num_addrs, ((num_addrs==1)?"":"es"), num_src_ports);

	// global initialization for send module
	assert(zconf.probe_module);
	if (zconf.probe_module->global_initialize) {
		zconf.probe_module->global_initialize(&zconf);
	}

	// concert specified bandwidth to packet rate
	if (zconf.bandwidth > 0) {
		int pkt_len = zconf.probe_module->packet_length;
		pkt_len *= 8;	
		pkt_len += 8*24;	// 7 byte MAC preamble, 1 byte Start frame, 
		                        // 4 byte CRC, 12 byte inter-frame gap
		if (pkt_len < 84*8) {
			pkt_len = 84*8;
		}
		if (zconf.bandwidth / pkt_len > 0xFFFFFFFF) {
			zconf.rate = 0;
		} else {
			zconf.rate = zconf.bandwidth / pkt_len;
			if (zconf.rate == 0) {
				log_warn("send", "bandwidth %lu bit/s is slower than 1 pkt/s, "
								"setting rate to 1 pkt/s", zconf.bandwidth);
				zconf.rate = 1;
			}
		}
		log_debug("send", "using bandwidth %lu bits/s, rate set to %d pkt/s",
						zconf.bandwidth, zconf.rate);
	}

	if (zconf.dryrun) {
		log_info("send", "dryrun mode -- won't actually send packets");
	}

	// initialize random validation key
	validate_init();

	zsend.start = now();	
	return EXIT_SUCCESS;
}

#ifdef ZMAP_PCAP_INJECT
pcap_t* get_pcap_t(void)
{
	pcap_t *pc = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	/* wbk return a pcap_t ready for pcap_inject */
	log_debug("send", "getting pcap handle");
	/* snaplen of 0 since we only write on this pcpa_t? */
	pc = pcap_open_live(zconf.iface, 0,
					PCAP_PROMISC, /* needed?*/
					PCAP_TIMEOUT,
					errbuf);
	if (pc == NULL) {
		log_fatal("send", "couldn't open device %s:, %s. "
					"Do you have permissions for the device?",
					zconf.iface, errbuf);
	}
	/*struct bpf_program bpf;
	//if (pcap_compile(pc, &bpf, zconf.probe_module->pcap_filter, 1, 0) < 0) {
	if (pcap_compile(pc, &bpf, zconf.probe_module->pcap_filter, 1, PCAP_NETMASK_UNKNOWN) < 0) {
		log_debug("send", "pcap_filter failed. Tried \"%s\"", 
							zconf.probe_module->pcap_filter);
		log_fatal("send", "couldn't compile filter");
	}
	if (pcap_setfilter(pc, &bpf) < 0) {
		log_fatal("send", "couldn't install filter");
	}*/
	log_debug("send", "injector ready");
	return pc;
}

static void get_hwaddr(unsigned char *hwaddr)  /* TODO determine ret type etc  -wbk**/
	/* error return or rely on log_fatal? TODO*/
{	
	/* pass a pointer to ETHER_ADDR_LEN bytes. */
	/* double check that interface name gets validated since
	   we use strcmp here. Unless there's some POSIX ocnstant for
	   max iface name (doubt it) IFNAMESIZ? */
	struct ifaddrs *p = NULL;
	struct sockaddr_dl* sdl = NULL; /* BSD-specific hardware address */

	if (getifaddrs(&p) == -1) {
		log_fatal("send", "get_hwaddr() getifaddrs() failed!");
		/* TODO: strerror() */

	}
	for (;p != NULL; p = p->ifa_next) {
		if ( (p->ifa_addr->sa_family == AF_LINK) /* linux would need AF_PACKET */
			&& (strncmp(zconf.iface, p->ifa_name, IF_NAMESIZE) == 0) ) 
		{
			/* copy MAC. Or get the whole sockaddr :). Eliminate sizeof()? */
			/* Linux has sockaddr_ll. BSD has sockaddr_dl. structs are differnent  */
			/* let's just get the hardware address to pass back. */
			sdl = (struct sockaddr_dl*)(p->ifa_addr);
			if (sdl->sdl_alen == ETHER_ADDR_LEN) /* paranoia */
				memcpy(hwaddr, LLADDR((sdl)),  sdl->sdl_alen);
			else
				log_fatal("send", "gethwaddr() unexpected sdl_alen!");
		}
	}
}

/*static void get_ipaddr(struct sockaddr *sa)*/
/* TODO: Is this even needed? */
static void get_ipaddr(struct in_addr *in)
{
	/* retrieve IPaddress using getifaddrs(), used by caller to craft packet for
	   pcap_inject(). TODO:see how nmap handles this. */
	struct ifaddrs *p = NULL;	
	struct sockaddr_in *sin = NULL;
	if (getifaddrs(&p) == -1) {
		log_fatal("send", "get_ipaddr() getifaddrs() failed!");
	}
	for (; p != NULL; p = p->ifa_next) {
		if ( (p->ifa_addr->sa_family == AF_INET)
			&& (strncmp(zconf.iface, p->ifa_name, IF_NAMESIZE) == 0) ) 
		{
			/* TODO: grab IPs a struct sockaddr_in I guess */
			sin = (struct sockaddr_in *)(p->ifa_addr);
			/* copy the struct in_addr for return*/
			/* TODO: Idon't like using sizeof() macro; see if there's a better alternative. */
			/* TODO:sanity check here? */
			memcpy(in, &(sin->sin_addr), sizeof(struct in_addr));
		}
	}
}
#else
int get_socket(void)
{
	int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock <= 0) {
		log_fatal("send", "couldn't create socket. "
			  "Are you root? Error: %s\n", strerror(errno));
	}
	return sock;
}
#endif

int get_dryrun_socket(void)
{
	// we need a socket in order to gather details about the system
	// such as source MAC address and IP address. However, because
	// we don't want to require root access in order to run dryrun,
	// we just create a TCP socket.
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock <= 0) {
		log_fatal("send", "couldn't create socket. "
			  "Error: %s\n", strerror(errno));
	}
	return sock;

}

static inline ipaddr_n_t get_src_ip(ipaddr_n_t dst, int local_offset)
{
	if (srcip_first == srcip_last) {
		return srcip_first;
	}
	return htonl(((ntohl(dst) + srcip_offset + local_offset) 
			% num_addrs)) + srcip_first;
}

// one sender thread
#ifdef ZMAP_PCAP_INJECT
int send_run(pcap_t *pc)
#else
int send_run(int sock)
#endif
{
	log_debug("send", "thread started");
	pthread_mutex_lock(&send_mutex);
#ifdef ZMAP_PCAP_INJECT
	/* Using pcap, mirror the linux SOCK_RAW behaviour as closely
	   as possible */
	unsigned char mac[ETHER_ADDR_LEN];
	struct in_addr src_ip = {0};
	//pcap_t *pc = get_pcap_t();
	/* We don't need the index; we have a pcap handle to the proper
	   interface */
	get_hwaddr(mac);
	get_ipaddr(&src_ip);

#else
	//int sock = get_socket();
	struct sockaddr_ll sockaddr;
	// get source interface index
	struct ifreq if_idx;
	memset(&if_idx, 0, sizeof(struct ifreq));
	if (strlen(zconf.iface) >= IFNAMSIZ) {
		log_error("send", "device interface name (%s) too long\n",
				zconf.iface);
		return -1;
	}
	strncpy(if_idx.ifr_name, zconf.iface, IFNAMSIZ-2);
	if (ioctl(sock, SIOCGIFINDEX, &if_idx) < 0) {
		perror("SIOCGIFINDEX");
		return -1;
	}
	int ifindex = if_idx.ifr_ifindex;
	// get source interface mac
	struct ifreq if_mac;
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, zconf.iface, IFNAMSIZ-1);
	if (ioctl(sock, SIOCGIFHWADDR, &if_mac) < 0) {
		perror("SIOCGIFHWADDR");
		return -1;
	}
	// find source IP address associated with the dev from which we're sending.
	// while we won't use this address for sending packets, we need the address
	// to set certain socket options and it's easiest to just use the primary
	// address the OS believes is associated.
	struct ifreq if_ip;
	memset(&if_ip, 0, sizeof(struct ifreq));
	strncpy(if_ip.ifr_name, zconf.iface, IFNAMSIZ-1);
	if (ioctl(sock, SIOCGIFADDR, &if_ip) < 0) {
		perror("SIOCGIFADDR");
		return -1;
	}
	// wbk TODO: gateway MAC.
	// destination address for the socket
	memset((void*) &sockaddr, 0, sizeof(struct sockaddr_ll));
	sockaddr.sll_ifindex = ifindex;
	sockaddr.sll_halen = ETH_ALEN;
	memcpy(sockaddr.sll_addr, zconf.gw_mac, ETH_ALEN);

#endif /* not ZMAP_PCAP_INJECT */ /* may move down... TODO wbk */

	char buf[MAX_PACKET_SIZE];
	memset(buf, 0, MAX_PACKET_SIZE);
	zconf.probe_module->thread_initialize(buf, 
#ifdef ZMAP_PCAP_INJECT
					mac,
#else
					(unsigned char *)if_mac.ifr_hwaddr.sa_data, 
#endif
					zconf.gw_mac, zconf.target_port);	
	pthread_mutex_unlock(&send_mutex);

	// adaptive timing to hit target rate
	uint32_t count = 0;
	uint32_t last_count = count;
	double last_time = now();
	uint32_t delay = 0;
	int interval = 0;
	volatile int vi;
	if (zconf.rate > 0) {
		// estimate initial rate
		delay = 10000;
		for (vi = delay; vi--; )
			;
		delay *= 1 / (now() - last_time) / (zconf.rate / zconf.senders);
		interval = (zconf.rate / zconf.senders) / 20;
		last_time = now();
	}
	while (1) {
		// adaptive timing delay
		if (delay > 0) {
			count++;
			for (vi = delay; vi--; )
				;
			if (!interval || (count % interval == 0)) {
				double t = now();
				delay *= (double)(count - last_count) 
					/ (t - last_time) / (zconf.rate / zconf.senders);
				if (delay < 1)
					delay = 1;
				last_count = count;
				last_time = t;
			}
		}
		// generate next ip from cyclic group and update global state
		// (everything locked happens here)
		pthread_mutex_lock(&send_mutex);
		if (zsend.complete) {
			pthread_mutex_unlock(&send_mutex);
			break;
		}
		if (zsend.sent >= zconf.max_targets) {
			zsend.complete = 1;
			zsend.finish = now();
			pthread_mutex_unlock(&send_mutex);
			break;
		}
		if (zconf.max_runtime && zconf.max_runtime <= now() - zsend.start) {
			zsend.complete = 1;
			zsend.finish = now();
			pthread_mutex_unlock(&send_mutex);
			break;
		}
		uint32_t curr = cyclic_get_next_ip();
		if (curr == zsend.first_scanned) {
			zsend.complete = 1;
			zsend.finish = now();
		}
		zsend.sent++;
		pthread_mutex_unlock(&send_mutex);
		for (int i=0; i < zconf.packet_streams; i++) {
			uint32_t src_ip = get_src_ip(curr, i);

		  	uint32_t validation[VALIDATE_BYTES/sizeof(uint32_t)];
			validate_gen(src_ip, curr, (uint8_t *)validation);
			zconf.probe_module->make_packet(buf, src_ip, curr, validation, i);

			if (zconf.dryrun) {
				zconf.probe_module->print_packet(stdout, buf);
			} else {
					int l = zconf.probe_module->packet_length;

#ifdef ZMAP_PCAP_INJECT
					int rc = pcap_inject(pc, buf, (size_t)l);
					if (rc == -1) {
						struct in_addr addr;
						addr.s_addr = curr;
						log_fatal("send", "pcap_inject() failed for %s. %s", /* TODO: make log_debug */
								  inet_ntoa(addr), strerror(errno));
						pthread_mutex_lock(&send_mutex);
						zsend.sendto_failures++;
						pthread_mutex_unlock(&send_mutex);
					}
#else /* TODO: error handling can be shared. */
					int rc = sendto(sock, buf + zconf.send_ip_pkts*sizeof(struct ethhdr),
							l, 0,
							(struct sockaddr *)&sockaddr,
							sizeof(struct sockaddr_ll));
					if (rc < 0) {
						struct in_addr addr;
						addr.s_addr = curr;
						log_debug("send", "sendto failed for %s. %s",
								  inet_ntoa(addr), strerror(errno));
						pthread_mutex_lock(&send_mutex);
						zsend.sendto_failures++;
						pthread_mutex_unlock(&send_mutex);
					}
#endif
			}
		}
	}
	log_debug("send", "thread finished");
	return EXIT_SUCCESS;
}

