#include "../state.h"
#include "../fieldset.h"

#ifndef PROBE_MODULES_H
#define PROBE_MODULES_H

#include "../proto_headers.h"

typedef struct probe_response_type {
		const uint8_t is_success;
		const char *name;
} response_type_t;

typedef int (*probe_global_init_cb)(struct state_conf *);
typedef int (*probe_thread_init_cb)(void* packetbuf, macaddr_t* src_mac,
		macaddr_t* gw_mac, port_n_t src_port);

typedef int (*probe_make_packet_cb)(void* packetbuf, ipaddr_n_t src_ip,
		ipaddr_n_t dst_ip,
		uint32_t *validation, int probe_num);

typedef void (*probe_print_packet_cb)(FILE *, void* packetbuf);
typedef int (*probe_close_cb)(struct state_conf*,
		struct state_send*, struct state_recv*);
#ifdef __FREEBSD__
typedef int (*probe_validate_packet_cb)(const struct zmap_iphdr *ip_hdr,
		uint32_t len, uint32_t *src_ip, uint32_t *validation);
#else
typedef int (*probe_validate_packet_cb)(const struct iphdr *ip_hdr,
		uint32_t len, uint32_t *src_ip, uint32_t *validation);
#endif
typedef void (*probe_classify_packet_cb)(const u_char* packetbuf,
		uint32_t len, fieldset_t*);

typedef struct probe_module {
	const char *name;
	size_t packet_length;
	const char *pcap_filter;
	size_t pcap_snaplen;

	// Should ZMap complain if the user hasn't specified valid
	// source and target port numbers?
	uint8_t port_args;

	probe_global_init_cb global_initialize;
	probe_thread_init_cb thread_initialize;
	probe_make_packet_cb make_packet;
	probe_print_packet_cb print_packet;
	probe_validate_packet_cb validate_packet;
	probe_classify_packet_cb process_packet;
	probe_close_cb close;
	fielddef_t *fields;
	int numfields;
	const char *helptext;

} probe_module_t;

probe_module_t* get_probe_module_by_name(const char*);

#ifdef __FREEBSD__
void fs_add_ip_fields(fieldset_t *fs, struct zmap_iphdr *ip);
#else
void fs_add_ip_fields(fieldset_t *fs, struct iphdr *ip);
#endif
void fs_add_system_fields(fieldset_t *fs, int is_repeat, int in_cooldown);
void print_probe_modules(void);

extern fielddef_t ip_fields[];
extern fielddef_t sys_fields[];

#endif // HEADER_PROBE_MODULES_H

