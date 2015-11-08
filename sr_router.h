/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 * Edited b: Marcela Melara 16 Mar 2014.
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
    char user[32]; /* user name */
    char host[32]; /* host name */ 
    char template[30]; /* template name if any */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    struct sr_arpcache cache;   /* ARP cache */
    pthread_attr_t attr;
    FILE* logfile;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

/* -- sr_arpcache.c and sr_router.c -- */
void sr_handle_arpreq(struct sr_instance* , struct sr_arpreq* );
/* LKS start */

/* called by sr_handle_arpreq */
/* when we give up to send arp request broadcast */
/* we need to inform the sender */
void send_icmp_host_unreachable(struct sr_instance* , struct sr_arpreq* );
/* used to send an arp request broadcast */
void send_arp_request(struct sr_instance* , struct sr_arpreq* );

/* called by sr_handlepacket */
/* used to handle ip/arp packet */
void process_ip(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface);
void process_arp(struct sr_instance* sr, uint8_t* packet, unsigned int len, char* interface);

/* called by process_ip */
/* used to forward packet if ip_dst is not router */
void forward_ip_packet(struct sr_instance* sr, sr_ip_hdr_t* ip_header);
/* used to handle icmp packet */
void process_icmp(struct sr_instance* sr, sr_ip_hdr_t* ip_header);

/* called by process arp */
/* used to send all packets of waiting ip when mac is known by router */
void sr_arpreq_send_all_packets(struct sr_instance* sr, struct sr_arpreq* req);
/* used to reply the arp request ask for mac of router */
void process_arp_request(struct sr_instance* sr, sr_arp_hdr_t* arp_header, struct sr_if* interface);

/* called by process_ip/process_arp/process_icmp */
/* used to verify if ip/arp/icmp packet is valid */
/* check if length valid and do checksum in ip/icmp */
int is_valid_ip_packet(uint8_t * packet, unsigned int len); /* only ipv4 */
int is_valid_arp_packet(uint8_t* packet, unsigned int len); /* only mac+ip */
int is_valid_icmp_packet(sr_ip_hdr_t* ip_header);			/* only echo request */

/* called by send_arp_request: used to encap arp request packet */
/* called by process_arp_request: used to encap arp responce packet */
/* called by forward_ip_packet: used to encap ip packet */
/* called by sr_send_icmp: used to encap icmp packet formed by ip packet */
/* called by sr_arpreq_send_all_packets: used to encap ip packet which ip just known by router */
void sr_make_eth_header_and_send(struct sr_instance* sr, uint8_t* packet, unsigned int len, uint32_t ip_dst, uint16_t type, int send_icmp);

/* called by send_icmp_host_unreachable: used to send host unreachable icmp packet */
/* called by process_ip: used to tell who send udp/tcp packet to router that port unreachable(traceroute) */
/* called by forward_ip_packet: used to tell sender the TTL=0(traceroute). */
/* called by make_eth_header: used to tell sender the dst is unreachable(no net call reach it). */
/* called by process_icmp: used to send echo reply icmp packet */
void sr_send_icmp(struct sr_instance* sr, uint8_t *packet, unsigned int len, uint8_t type, uint8_t code);
/* note: 
When packet's TTL=0, the packet will be dropped and router will responce Time Exceeded(11,0).
When you trying a invalid port, the dst will responce port unreachable, and you know you arrived dst(3,3).
*/
/* LKS end */

#endif /* SR_ROUTER_H */
