/*
 * ZMap Copyright 2013 Regents of the University of Michigan 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#ifndef SEND_H
#define SEND_H

#include <stdint.h> /* for uintptr_t ? */
#ifdef ZMAP_PCAP_INJECT
#include <pcap/pcap.h>
#else
#endif

/* wrapper for Linux socket handle or pcap_t. BSD port uses 
   pcap_inject() instead of Linux SOCK_RAW sendto(). 
   This is an ugly hack. Client code will need to check 
   zconf for dryrun, and if ZMAP_PCAP_INJECT, use pcap_t,
   otherwise sock.*/
struct send_handle {
#ifdef ZMAP_PCAP_INJECT
	pcap_t *pc;
#endif
	//int sock;
	uintptr_t sock;
};

int get_socket(void);
int get_dryrun_socket(void);
int send_init(void);
#ifdef ZMAP_PCAP_INJECT
pcap_t *get_pcap_t(void);
int send_run(pcap_t *pc); 
#else
int send_run(int); 
#endif

#endif //SEND_H
