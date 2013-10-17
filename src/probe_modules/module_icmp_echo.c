/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

// probe module for performing ICMP echo request (ping) scans

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <string.h>

#ifndef __FREEBSD__
#include <netinet/ether.h>
#endif
#include <netinet/in.h> /* wbk order */
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include "probe_modules.h"
#include "../fieldset.h"
#include "packet.h"
#include "validate.h"

probe_module_t module_icmp_echo;

int icmp_echo_init_perthread(void* buf, macaddr_t *src,
		macaddr_t *gw, __attribute__((unused)) port_h_t dst_port)
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
	uint16_t len = htons(sizeof(struct zmap_iphdr) + sizeof(struct icmp) - 8);
#else
	struct iphdr *ip_header = (struct iphdr*)(&eth_header[1]);
	uint16_t len = htons(sizeof(struct iphdr) + sizeof(struct icmp) - 8);
#endif
	make_ip_header(ip_header, IPPROTO_ICMP, len);

	struct icmp *icmp_header = (struct icmp*)(&ip_header[1]);
	make_icmp_header(icmp_header);

	return EXIT_SUCCESS;
}

int icmp_echo_make_packet(void *buf, ipaddr_n_t src_ip, ipaddr_n_t dst_ip,
				uint32_t *validation, __attribute__((unused))int probe_num)
{
#ifdef __FREEBSD__
	struct zmap_ethhdr *eth_header = (struct zmap_ethhdr *)buf;
	struct zmap_iphdr *ip_header = (struct zmap_iphdr*)(&eth_header[1]);
#else
	struct ethhdr *eth_header = (struct ethhdr *)buf;
	struct iphdr *ip_header = (struct iphdr*)(&eth_header[1]);
#endif
	struct icmp *icmp_header = (struct icmp*)(&ip_header[1]); /* TODO: struct icmp? */
	uint16_t icmp_idnum = validation[2] & 0xFFFF;

#ifdef __FREEBSD__
	ip_header->saddr.s_addr = src_ip;
	ip_header->daddr.s_addr = dst_ip;
#else
	ip_header->saddr = src_ip;
	ip_header->daddr = dst_ip;
#endif

	icmp_header->icmp_id = icmp_idnum;
	icmp_header->icmp_cksum = 0;
	icmp_header->icmp_cksum = icmp_checksum((unsigned short *) icmp_header);

	ip_header->check = 0;
	ip_header->check = ip_checksum((unsigned short *) ip_header);

	return EXIT_SUCCESS;
}

void icmp_echo_print_packet(FILE *fp, void* packet)
{
#ifdef __FREEBSD__
	struct zmap_ethhdr *ethh = (struct zmap_ethhdr *) packet;
	struct zmap_iphdr *iph = (struct zmap_iphdr *) &ethh[1];
#else
	struct ethhdr *ethh = (struct ethhdr *) packet;
	struct iphdr *iph = (struct iphdr *) &ethh[1];
#endif
	struct icmp *icmp_header = (struct icmp*)(&iph[1]);

	fprintf(fp, "icmp { type: %u | code: %u "
			"| checksum: %u | id: %u | seq: %u }\n",
			icmp_header->icmp_type,
			icmp_header->icmp_code,
			ntohs(icmp_header->icmp_cksum),
			ntohs(icmp_header->icmp_id),
			ntohs(icmp_header->icmp_seq));
	fprintf_ip_header(fp, iph);
	fprintf_eth_header(fp, ethh);
	fprintf(fp, "------------------------------------------------------\n");
}

#ifdef __FREEBSD__
int icmp_validate_packet(const struct zmap_iphdr *ip_hdr, 
		uint32_t len, uint32_t *src_ip, uint32_t *validation)
#else
int icmp_validate_packet(const struct iphdr *ip_hdr, 
		uint32_t len, uint32_t *src_ip, uint32_t *validation)
#endif
{
	if (ip_hdr->protocol != IPPROTO_ICMP) {
		return 0;
	}
	
	if ((4*ip_hdr->ihl + sizeof(struct icmphdr)) > len) {
		// buffer not large enough to contain expected icmp header 
		return 0;
	}
	
#ifdef __FREEBSD__
	struct zmap_icmphdr *icmp_h = (struct zmap_icmphdr*)((char *)ip_hdr + 4*ip_hdr->ihl);
#else
	struct icmphdr *icmp_h = (struct icmphdr*)((char *)ip_hdr + 4*ip_hdr->ihl);
#endif
	uint16_t icmp_idnum = icmp_h->un.echo.id;

	// ICMP validation is tricky: for some packet types, we must look inside 
	// the payload
	if (icmp_h->type == ICMP_TIME_EXCEEDED || icmp_h->type == ICMP_DEST_UNREACH) {
		if ((4*ip_hdr->ihl + sizeof(struct icmphdr) +
#ifdef __FREEBSD__
			sizeof(struct zmap_iphdr)) > len) {
#else
			sizeof(struct iphdr)) > len) {
#endif
			return 0;
		}
#ifdef __FREEBSD__
		struct zmap_iphdr *ip_inner = (struct zmap_iphdr *)(icmp_h + 1);
		if ((4*ip_hdr->ihl + sizeof(struct zmap_icmphdr) +
				4*ip_inner->ihl + sizeof(struct zmap_icmphdr)) > len) {
#else
		struct iphdr *ip_inner = (struct iphdr *)(icmp_h + 1);
		if ((4*ip_hdr->ihl + sizeof(struct icmphdr) +
				4*ip_inner->ihl + sizeof(struct icmphdr)) > len) {
#endif
			return 0;
		}
#ifdef __FREEBSD__
		struct zmap_icmphdr *icmp_inner = (struct zmap_icmphdr*)((char *)ip_inner + 4 *ip_hdr->ihl);
#else
		struct icmphdr *icmp_inner = (struct icmphdr*)((char *)ip_inner + 4 *ip_hdr->ihl);
#endif

		// Regenerate validation and icmp id based off inner payload
		icmp_idnum = icmp_inner->un.echo.id;
#ifdef __FREEBSD__
		*src_ip = ip_inner->daddr.s_addr;
		validate_gen(ip_hdr->daddr.s_addr, ip_inner->daddr.s_addr, (uint8_t *)validation);
#else
		*src_ip = ip_inner->daddr;
		validate_gen(ip_hdr->daddr, ip_inner->daddr, (uint8_t *)validation);
#endif
	} 

	// validate icmp id
	if (icmp_idnum != (validation[2] & 0xFFFF)) {
		return 0;
	}

	return 1;
}

void icmp_echo_process_packet(const u_char *packet,
		__attribute__((unused)) uint32_t len, fieldset_t *fs)
{
#ifdef __FREEBSD__
	struct zmap_iphdr *ip_hdr = (struct zmap_iphdr *)&packet[sizeof(struct zmap_ethhdr)];
	struct zmap_icmphdr *icmp_hdr = (struct zmap_icmphdr*)((char *)ip_hdr + 4 *ip_hdr->ihl);
#else
	struct iphdr *ip_hdr = (struct iphdr *)&packet[sizeof(struct ethhdr)];
	struct icmphdr *icmp_hdr = (struct icmphdr*)((char *)ip_hdr + 4 *ip_hdr->ihl);
#endif
	fs_add_uint64(fs, "type", icmp_hdr->type);
	fs_add_uint64(fs, "code", icmp_hdr->code);
	fs_add_uint64(fs, "icmp-id", ntohs(icmp_hdr->un.echo.id));
	fs_add_uint64(fs, "seq", ntohs(icmp_hdr->un.echo.sequence));
	switch (icmp_hdr->type) {
		case ICMP_ECHOREPLY:
			fs_add_string(fs, "classification", (char*) "echoreply", 0); 
			fs_add_uint64(fs, "success", 1); 
		case ICMP_UNREACH: 
			fs_add_string(fs, "classification", (char*) "unreach", 0); 
			fs_add_uint64(fs, "success", 0); 
		case ICMP_SOURCEQUENCH:
			fs_add_string(fs, "classification", (char*) "sourcequench", 0); 
			fs_add_uint64(fs, "success", 0); 
		case ICMP_REDIRECT:
			fs_add_string(fs, "classification", (char*) "redirect", 0); 
			fs_add_uint64(fs, "success", 0); 
		case ICMP_TIMXCEED:
			fs_add_string(fs, "classification", (char*) "timxceed", 0); 
			fs_add_uint64(fs, "success", 0); 
		default:
			fs_add_string(fs, "classification", (char*) "other", 0); 
			fs_add_uint64(fs, "success", 0); 
	}
}

fielddef_t fields[] = {
	{.name="type", .type="int", .desc="icmp message type"},
	{.name="code", .type="int", .desc="icmp message sub type code"},
	{.name="icmp-id", .type="int", .desc="icmp id number"},
	{.name="seq", .type="int", .desc="icmp sequence number"},
	{.name="classification", .type="string", .desc="probe module classification"},
	{.name="success", .type="int", .desc="did probe module classify response as success"}
};


probe_module_t module_icmp_echo = {
	.name = "icmp_echoscan",
	.packet_length = 62,
	.pcap_filter = "icmp and icmp[0]!=8",
	.pcap_snaplen = 96,
	.port_args = 0,
	.thread_initialize = &icmp_echo_init_perthread,
	.make_packet = &icmp_echo_make_packet,
	.print_packet = &icmp_echo_print_packet,
	.process_packet = &icmp_echo_process_packet,
	.validate_packet = &icmp_validate_packet,
	.close = NULL,
	.fields = fields,
	.numfields = 6};

