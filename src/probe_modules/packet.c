/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "packet.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifndef __FREEBSD__
#include <netinet/ether.h>
#endif
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#include <net/if.h>
#include <arpa/inet.h>
#include <assert.h>

#include "state.h"

#ifdef __FREEBSD__
#include "../proto_headers.h"
#endif

#ifdef __FREEBSD_INCLUDES__ /* some macros in Linux system headers */
#define ETH_ALEN ETHER_ADDR_LEN
#define ETH_P_IP ETYPE_IPV4 /* EtherType 0x800 */
#endif

#ifndef __FREEBSD__ /* TODO: */
void print_macaddr(struct ifreq* i)
{
	printf("Device %s -> Ethernet %02x:%02x:%02x:%02x:%02x:%02x\n",
			i->ifr_name,
			(int) ((unsigned char *) &i->ifr_hwaddr.sa_data)[0],
			(int) ((unsigned char *) &i->ifr_hwaddr.sa_data)[1],
			(int) ((unsigned char *) &i->ifr_hwaddr.sa_data)[2],
			(int) ((unsigned char *) &i->ifr_hwaddr.sa_data)[3],
			(int) ((unsigned char *) &i->ifr_hwaddr.sa_data)[4],
			(int) ((unsigned char *) &i->ifr_hwaddr.sa_data)[5]);
}
#endif

#ifdef __FREEBSD__
void fprintf_ip_header(FILE *fp, struct zmap_iphdr *iph)
#else
void fprintf_ip_header(FILE *fp, struct iphdr *iph)
#endif
{
	struct in_addr *s = (struct in_addr *) &(iph->saddr);
	struct in_addr *d = (struct in_addr *) &(iph->daddr);
	char srcip[20];
	char dstip[20];
	// inet_ntoa is a const char * so we if just call it in
	// fprintf, you'll get back wrong results since we're
	// calling it twice.
	strncpy(srcip, inet_ntoa(*s), 19);
	strncpy(dstip, inet_ntoa(*d), 19);
	fprintf(fp, "ip { saddr: %s | daddr: %s | checksum: %u }\n",
			srcip,
			dstip,
			ntohl(iph->check));
}

#ifdef __FREEBSD__
void fprintf_eth_header(FILE *fp, struct zmap_ethhdr *ethh)
#else
void fprintf_eth_header(FILE *fp, struct ethhdr *ethh)
#endif
{
	fprintf(fp, "eth { shost: %02x:%02x:%02x:%02x:%02x:%02x | "
			"dhost: %02x:%02x:%02x:%02x:%02x:%02x }\n",
			(int) ((unsigned char *) ethh->h_source)[0],
			(int) ((unsigned char *) ethh->h_source)[1],
			(int) ((unsigned char *) ethh->h_source)[2],
			(int) ((unsigned char *) ethh->h_source)[3],
			(int) ((unsigned char *) ethh->h_source)[4],
			(int) ((unsigned char *) ethh->h_source)[5],
			(int) ((unsigned char *) ethh->h_dest)[0],
			(int) ((unsigned char *) ethh->h_dest)[1],
			(int) ((unsigned char *) ethh->h_dest)[2],
			(int) ((unsigned char *) ethh->h_dest)[3],
			(int) ((unsigned char *) ethh->h_dest)[4],
			(int) ((unsigned char *) ethh->h_dest)[5]);
}

#ifdef __FREEBSD__
void make_eth_header(struct zmap_ethhdr *ethh, macaddr_t *src, macaddr_t *dst)
#else
void make_eth_header(struct ethhdr *ethh, macaddr_t *src, macaddr_t *dst)
#endif
{
	memcpy(ethh->h_source, src, ETH_ALEN);
	memcpy(ethh->h_dest, dst, ETH_ALEN);
	ethh->h_proto = htons(ETH_P_IP);
}

#ifdef __FREEBSD__
void make_ip_header(struct zmap_iphdr *iph, uint8_t protocol, uint16_t len)
#else
void make_ip_header(struct iphdr *iph, uint8_t protocol, uint16_t len)
#endif
{	   
	iph->ihl = 5; // Internet Header Length
	iph->version = 4; // IPv4
	iph->tos = 0; // Type of Service
	iph->tot_len = len; 
	iph->id = htons(54321); // identification number
	iph->frag_off = 0; //fragmentation falg
	iph->ttl = MAXTTL; // time to live (TTL)
	iph->protocol = protocol; // upper layer protocol => TCP
	// we set the checksum = 0 for now because that's
	// what it needs to be when we run the IP checksum
	iph->check = 0;
}

void make_icmp_header(struct icmp *buf)
{
	buf->icmp_type = ICMP_ECHO;
	buf->icmp_code = 0;
	buf->icmp_seq = 0;
}
/* TODO: This is sketchy when linking against other translation units.
   Probably need to reconcile the struct names properly */


#ifdef __FREEBSD__
void make_tcp_header(struct zmap_tcphdr *tcp_header, port_h_t dest_port)
{
	tcp_header->seq = random();
	tcp_header->ack_seq = 0;
	tcp_header->th_flags = 0;
	tcp_header->th_flags = 5 << 4; /* data offset */
	tcp_header->th_flags &= TH_SYN;
	tcp_header->th_win = htons(65535);
	tcp_header->check = 0;
	tcp_header->th_urp = 0;
	tcp_header->dest = (htons(dest_port));
#else
void make_tcp_header(struct tcphdr *tcp_header, port_h_t dest_port)
{
    tcp_header->seq = random();
    tcp_header->ack_seq = 0;
    tcp_header->res2 = 0;
    tcp_header->doff = 5; // data offset 
    tcp_header->syn = 1;
    tcp_header->window = htons(65535); // largest possible window
    tcp_header->check = 0;
    tcp_header->urg_ptr = 0;
    tcp_header->dest = htons(dest_port);
#endif
}

#ifdef __FREEBSD__
void make_udp_header(struct zmap_udphdr *udp_header, port_h_t dest_port,
#else
void make_udp_header(struct udphdr *udp_header, port_h_t dest_port,
#endif
				uint16_t len)
{
	udp_header->dest = htons(dest_port);
	udp_header->len = htons(len);
	// checksum ignored in IPv4 if 0
	udp_header->check = 0;
}

// Note: caller must free return value
char *make_ip_str(uint32_t ip)
{
	struct in_addr t;
	t.s_addr = ip;
	const char *temp = inet_ntoa(t);
	char *retv = malloc(strlen(temp)+1);
	assert (retv);
	strcpy(retv, temp);
	return retv;
}


