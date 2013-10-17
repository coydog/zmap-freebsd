#ifndef HEADER_PROTO_HEADERS_H
#define HEADER_PROTO_HEADERS_H
/* struct definitions for accessing frames and packets */

/* Initially copied from Tim Carsten's "sniffex" example from tcpdump.org.
   Macros are all that remain. Though it's almost 100% modified,
   here is his permissive license to be on the safe side: 					*/

/* This document is Copyright 2002 Tim Carstens. All rights reserved. 
   Redistribution and use, with or without modification, are permitted 
   provided that the following conditions are met:
       Redistribution must retain the above copyright notice and this
	   list of conditions.
	   The name of Tim Carstens may not be used to endorse or promote
	   products derived from this document without specific prior
	   written permission. */
/*
 ****************************************************************************
 *
 * This software is a modification of Tim Carstens' "sniffer.c"
 * demonstration source code, released as follows:
 * 
 * sniffer.c
 * Copyright (c) 2002 Tim Carstens
 * 2002-01-07
 * Demonstration of using libpcap
 * timcarst -at- yahoo -dot- com
 * 
 * "sniffer.c" is distributed under these terms:
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. The name "Tim Carstens" may not be used to endorse or promote
 *    products derived from this software without prior written permission
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * <end of "sniffer.c" terms>
 */

//#include <sys/types.h> 		/* for u_char, uint16_t and the like */
#include <stdint.h> 		/* for u_char, uint16_t and the like */
#include <netinet/in.h> 	/* for in_addr 	*/
//#include <netinet/tcp.h>	/* for tcp_seq	*/ /* TODO: get it out? too dangerous? */

/* Macros that may already exist on Linux but not other platforms. */
/* Ethernet addresses are 6 bytes */
#ifndef ETHER_ADDR_LEN
	#define ETHER_ADDR_LEN	6
#endif
#ifndef ETHER_HDR_LEN
	#define ETHER_HDR_LEN	14	/* wbk - adding to avoid sizeof(sniff_ethernet) */
#endif
#ifndef IFHWADDRLEN
	#define IFHWADDRLEN ETHER_ADDR_LEN
#endif

	struct zmap_ethhdr { 
		u_char h_dest[ETHER_ADDR_LEN];
		u_char h_source[ETHER_ADDR_LEN];
		uint16_t h_proto;
		#define ETYPE_IPV4 	0x0800
		#define ETYPE_IPV6	0x86dd
		#define ETYPE_ARP 	0x0806
		#define ETYPE_RARP	0x8035
	};

	struct zmap_iphdr {
		/* wbk TODO: This bitfield stuff will almost certainly need to go, but will
		   complicate client code. */
		u_char ihl:4,
			   version:4;
		u_char tos;
		uint16_t tot_len;
		uint16_t id;
		uint16_t frag_off;
		u_char ttl;
		u_char protocol;
		uint16_t check;
		struct in_addr saddr, daddr;
		#define IP_FLAGMASK 0xe000	/* flags are first 3 bits of ip_off - wbk */
		#define IP_RF 0x8000		/* reserved fragment flag */
		#define IP_DF 0x4000		/* dont fragment flag */
		#define IP_MF 0x2000		/* more fragments flag */
		#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
		#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
		#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

	};	

	struct zmap_tcphdr { 	/* TODO: maybe change to zmap_tcphdr?*/
		uint16_t source;		/* source port */
		uint16_t dest;		/* destination port */
		uint32_t seq;		/* sequence number */ /*TODO type tcp_seq? */
		uint32_t ack_seq;		/* acknowledgement number */

		u_char th_offx2;	/* data offset, rsvd */
		#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
		u_char th_flags;
		#define TH_FIN 0x01
		#define TH_SYN 0x02
		#define TH_RST 0x04
		#define TH_PUSH 0x08
		#define TH_ACK 0x10
		#define TH_URG 0x20
		#define TH_ECE 0x40
		#define TH_CWR 0x80
		#ifndef TH_FLAGS /* wbk - FreeBSD has equivalent in netinet/tcp.h */
			#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
		#endif 
		uint16_t th_win;		/* window */
		uint16_t check;		/* checksum */
		uint16_t th_urp;		/* urgent pointer */
	};

	struct zmap_udphdr {
		uint16_t source;
		uint16_t dest;
		uint16_t len;
		uint16_t check;
	};

#ifndef ICMP_HDR_LEN
	#define ICMP_HDR_LEN 64
#endif
	struct zmap_icmphdr {
		uint8_t type;
		uint8_t code;
		uint16_t checksum;
		/*uint16_t id; / * this part is different for different ICMP services * /
		uint16_t seq; */
		union {
			struct {
				uint16_t id;
				uint16_t sequence;
			} echo;
			uint32_t gateway;
			struct { // TODO: check this. Perfect overlap causing warnings?
				uint16_t __unused;
				uint16_t mtu;
			} frag;
		} un;
	#ifndef ICMP_ECHO
		#define ICMP_ECHO 				8
	#endif
	#ifndef ICMP_ECHOREPLY
		#define ICMP_ECHOREPLY			0
	#endif
	#ifndef ICMP_TIME_EXCEEDED
		#define ICMP_TIME_EXCEEDED		11
	#endif
	#ifndef ICMP_DEST_UNREACH
		#define ICMP_DEST_UNREACH		3
	#endif
	#ifndef ICMP_PREC_CUTOFF
		#define ICMP_PREC_CUTOFF			15	
	#endif	
	};
#endif /* HEADER_PROTO_HEADERS_H */
