/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

// probe module for performing TCP SYN scans 

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#ifdef __FREEBSD__ // TODO: __FREEBSD_INCLUDES__?
	/* TODO: This may break Linux, might need to remove #ifdef here entirely */
	#include <netinet/in.h> /* wbk needed before netinet/ip.h */
#endif
#include <netinet/ip.h>
#include <netinet/tcp.h>
#ifdef __FREEBSD__
#else
	#include <netinet/ether.h>
#endif

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../fieldset.h"
#include "probe_modules.h"
#include "packet.h"

probe_module_t module_tcp_synscan;
static uint32_t num_ports;

int synscan_global_initialize(struct state_conf *state)
{
	num_ports = state->source_port_last - state->source_port_first + 1;
	return EXIT_SUCCESS;
}

int synscan_init_perthread(void* buf, macaddr_t *src,
		macaddr_t *gw, port_h_t dst_port)
{
	memset(buf, 0, MAX_PACKET_SIZE);
#ifdef __FREEBSD__
	struct zmap_ethhdr *eth_header = (struct zmap_ethhdr *)buf;
#else
	struct ethhdr *eth_header = (struct ethhdr *)buf;
#endif
	make_eth_header(eth_header, src, gw);
#ifdef __FREEBSD__
	struct zmap_iphdr *ip_header = (struct zmap_iphdr*)(&eth_header[1]);
	uint16_t len = htons(sizeof(struct zmap_iphdr) + sizeof(struct zmap_tcphdr));
#else
	struct iphdr *ip_header = (struct iphdr*)(&eth_header[1]);
	uint16_t len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
#endif
	make_ip_header(ip_header, IPPROTO_TCP, len);
#ifdef __FREEBSD__
	struct zmap_tcphdr *tcp_header = (struct zmap_tcphdr*)(&ip_header[1]);
#else
	struct tcphdr *tcp_header = (struct tcphdr*)(&ip_header[1]);
#endif
	make_tcp_header(tcp_header, dst_port);
	return EXIT_SUCCESS;
}

int synscan_make_packet(void *buf, ipaddr_n_t src_ip, ipaddr_n_t dst_ip,
		uint32_t *validation, int probe_num)
{
#ifdef __FREEBSD__
	struct zmap_ethhdr *eth_header = (struct zmap_ethhdr *)buf;
	struct zmap_iphdr *ip_header = (struct zmap_iphdr*)(&eth_header[1]);
	struct zmap_tcphdr *tcp_header = (struct zmap_tcphdr*)(&ip_header[1]); /* How does this work? What about options? */
#else
	struct ethhdr *eth_header = (struct ethhdr *)buf;
	struct iphdr *ip_header = (struct iphdr*)(&eth_header[1]);
	struct tcphdr *tcp_header = (struct tcphdr*)(&ip_header[1]);
#endif
	uint32_t tcp_seq = validation[0];

#ifdef __FREEBSD__
	ip_header->saddr.s_addr = src_ip;
	ip_header->daddr.s_addr = dst_ip;
#else
	ip_header->saddr = src_ip;
	ip_header->daddr = dst_ip;
#endif

	tcp_header->source = htons(get_src_port(num_ports,
				probe_num, validation));
	tcp_header->seq = tcp_seq;
	tcp_header->check = 0;
#ifdef __FREEBSD__
	tcp_header->check = tcp_checksum(sizeof(struct zmap_tcphdr),
			ip_header->saddr.s_addr, ip_header->daddr.s_addr, tcp_header);

	/* wbk Set TCP data offset. I think Linux SOCK_RAW might have set this for us
	   on Linux. Hardcoding for now.  */
	//tcp_header->th_offx2 = 0x50;
	//tcp_header->th_flags = 0x02;
	/* If we ever add TCP options, we'll need to calculate header length in words and replace
	   5 with that. */
	tcp_header->th_offx2 = (0x5 << 4);
	tcp_header->th_flags = TH_SYN;
#else
	tcp_header->check = tcp_checksum(sizeof(struct tcphdr),
			ip_header->saddr, ip_header->daddr, tcp_header);
#endif

	ip_header->check = 0;
	ip_header->check = ip_checksum((unsigned short *) ip_header);

	return EXIT_SUCCESS;
}

void synscan_print_packet(FILE *fp, void* packet)
{
#ifdef __FREEBSD__
	struct zmap_ethhdr *ethh = (struct zmap_ethhdr *) packet;
	struct zmap_iphdr *iph = (struct zmap_iphdr *) &ethh[1];
	struct zmap_tcphdr *tcph = (struct zmap_tcphdr *) &iph[1];
#else
	struct ethhdr *ethh = (struct ethhdr *) packet;
	struct iphdr *iph = (struct iphdr *) &ethh[1];
	struct tcphdr *tcph = (struct tcphdr *) &iph[1];
#endif
	fprintf(fp, "tcp { source: %u | dest: %u | seq: %u | checksum: %u }\n",
			ntohs(tcph->source),
			ntohs(tcph->dest),
			ntohl(tcph->seq),
			ntohl(tcph->check));
	fprintf_ip_header(fp, iph);
	fprintf_eth_header(fp, ethh);
	fprintf(fp, "------------------------------------------------------\n");
}

#ifdef __FREEBSD__
int synscan_validate_packet(const struct zmap_iphdr *ip_hdr, uint32_t len, 
		__attribute__((unused))uint32_t *src_ip, 
		uint32_t *validation)
#else
int synscan_validate_packet(const struct iphdr *ip_hdr, uint32_t len, 
		__attribute__((unused))uint32_t *src_ip, 
		uint32_t *validation)
#endif
{
	if (ip_hdr->protocol != IPPROTO_TCP) {
		return 0;
	}
	if ((4*ip_hdr->ihl + sizeof(struct tcphdr)) > len) {
		// buffer not large enough to contain expected tcp header 
		return 0;
	}
#ifdef __FREEBSD__
	struct zmap_tcphdr *tcp = (struct zmap_tcphdr*)((char *)ip_hdr + 4*ip_hdr->ihl);/*TODO*/
#else
	struct tcphdr *tcp = (struct tcphdr*)((char *)ip_hdr + 4*ip_hdr->ihl);
#endif
	uint16_t sport = tcp->source;
	uint16_t dport = tcp->dest;
	// validate source port
	if (ntohs(sport) != zconf.target_port) {
		return 0;
	}
	// validate destination port
	if (!check_dst_port(ntohs(dport), num_ports, validation)) {
		return 0;
	}
	// validate tcp acknowledgement number
	if (htonl(tcp->ack_seq) != htonl(validation[0])+1) {
		return 0;
	}
	return 1;
}

void synscan_process_packet(const u_char *packet,
		__attribute__((unused)) uint32_t len, fieldset_t *fs)
{
#ifdef __FREEBSD__
	struct zmap_iphdr *ip_hdr = (struct zmap_iphdr *)&packet[sizeof(struct zmap_ethhdr)];
	struct zmap_tcphdr *tcp = (struct zmap_tcphdr*)((char *)ip_hdr 
					+ (sizeof(struct zmap_iphdr)));
#else
	struct iphdr *ip_hdr = (struct iphdr *)&packet[sizeof(struct ethhdr)];
	struct tcphdr *tcp = (struct tcphdr*)((char *)ip_hdr 
					+ (sizeof(struct iphdr)));
#endif

	fs_add_uint64(fs, "sport", (uint64_t) ntohs(tcp->source)); 
	fs_add_uint64(fs, "dport", (uint64_t) ntohs(tcp->dest));
	fs_add_uint64(fs, "seqnum", (uint64_t) ntohl(tcp->seq));
	fs_add_uint64(fs, "acknum", (uint64_t) ntohl(tcp->ack_seq));
#ifdef __FREEBSD__
	fs_add_uint64(fs, "window", (uint64_t) ntohs(tcp->th_win));
#else
	fs_add_uint64(fs, "window", (uint64_t) ntohs(tcp->window));
#endif

#ifdef __FREEBSD__
	if (tcp->th_flags & TH_RST) { // RST packet
#else
	if (tcp->rst) { // RST packet
#endif
		fs_add_string(fs, "classification", (char*) "rst", 0);
		fs_add_uint64(fs, "success", 0);
	} else { // SYNACK packet
		fs_add_string(fs, "classification", (char*) "synack", 0);
		fs_add_uint64(fs, "success", 1);
	}
}

static fielddef_t fields[] = {
	{.name = "sport",  .type = "int", .desc = "TCP source port"},
	{.name = "dport",  .type = "int", .desc = "TCP destination port"},
	{.name = "seqnum", .type = "int", .desc = "TCP sequence number"},
	{.name = "acknum", .type = "int", .desc = "TCP acknowledgement number"},
	{.name = "window", .type = "int", .desc = "TCP window"},
	{.name = "classification", .type="string", .desc = "packet classification"},
	{.name = "success", .type="int", .desc = "is response considered success"}
};

probe_module_t module_tcp_synscan = {
	.name = "tcp_synscan",
	.packet_length = 54,
	.pcap_filter = "tcp && tcp[13] & 4 != 0 || tcp[13] == 18",
	.pcap_snaplen = 96,
	.port_args = 1,
	.global_initialize = &synscan_global_initialize,
	.thread_initialize = &synscan_init_perthread,
	.make_packet = &synscan_make_packet,
	.print_packet = &synscan_print_packet,
	.process_packet = &synscan_process_packet,
	.validate_packet = &synscan_validate_packet,
	.close = NULL,
	.helptext = "Probe module that sends a TCP SYN packet to a specific "
		"port. Possible classifications are: synack and rst. A "
		"SYN-ACK packet is considered a success and a reset packet "
		"is considered a failed response.",

	.fields = fields,
	.numfields = 7};

