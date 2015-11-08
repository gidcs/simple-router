/*
 *  Copyright (c) 2009 Roger Liao <rogliao@cs.stanford.edu>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifndef SR_UTILS_H
#define SR_UTILS_H

#include <netinet/in.h>
#include <arpa/inet.h>
#include "sr_if.h"

uint16_t cksum(const void *_data, int len);

uint16_t ethertype(uint8_t *buf);
uint8_t ip_protocol(uint8_t *buf);

/* LKS start */
/* remove mac header */
sr_ip_hdr_t* get_ip_header(uint8_t* buf);
sr_arp_hdr_t* get_arp_header(uint8_t* buf);

/* remove ip header */
sr_icmp_hdr_t* get_icmp_header(sr_ip_hdr_t* ip_header);

/* read parameter in ip packet */
uint16_t get_ip_packet_len(sr_ip_hdr_t* ip_header);
uint8_t get_ip_header_len(sr_ip_hdr_t* ip_header);

/* read parameter in arp packet */
uint16_t get_arp_op(sr_arp_hdr_t* arp_header);
uint16_t get_arp_hrd(sr_arp_hdr_t* arp_header);
uint16_t get_arp_pro(sr_arp_hdr_t* arp_header);

/* convert uint32_t ip to in_addr type */
struct in_addr convert_to_in_addr(uint32_t ip);

/* longest prefix match of ip_addr */
/* only the ip_addr actually match in routing table will return routing entry */
struct sr_rt *sr_longest_prefix_match(struct sr_instance* sr, struct in_addr addr);
/* LKS end */

void print_addr_eth(uint8_t *addr);
void print_addr_ip(struct in_addr address);
void print_addr_ip_int(uint32_t ip);

void print_hdr_eth(uint8_t *buf);
void print_hdr_ip(uint8_t *buf);
void print_hdr_icmp(uint8_t *buf);
void print_hdr_arp(uint8_t *buf);

/* prints all headers, starting from eth */
void print_hdrs(uint8_t *buf, uint32_t length);

#endif /* -- SR_UTILS_H -- */
