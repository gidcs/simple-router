/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/**/
#define DEBUG
/**/

#ifdef DEBUG
#define DEBUG_PRINT(fmt, args...)    fprintf(stderr, fmt, ## args)
#else
#define DEBUG_PRINT(fmt, args...)    /* Don't do anything in release builds */
#endif

/* TODO: Add constant definitions here... */
#define MIN_IP_HDR_LEN 20 
#define MAX_IP_HDR_LEN 60
#define DEFAULT_TTL 64

/* TODO: Add helper functions here... */

/* See pseudo-code in sr_arpcache.h */
void sr_handle_arpreq(struct sr_instance* sr, struct sr_arpreq* req){
  /* TODO: Fill this in */
	/* LKS start */
	if (difftime(time(NULL), req->sent) > 1.0){ /* Last sent time: req->sent */
		/* this sent req pass 1s */
		if (req->times_sent >= 5){
			/* give up */
			DEBUG_PRINT("[LKS] (sr_handle_arpreq) no response for 5s, give up.\n");
			DEBUG_PRINT("[LKS] (sr_handle_arpreq) call send_icmp_host_unreachable.\n");
			send_icmp_host_unreachable(sr,req);
			sr_arpreq_destroy(&(sr->cache),req);
		}
		else{
			/* try again */
			DEBUG_PRINT("[LKS] (sr_handle_arpreq) no response for 1s, try again.\n");
			DEBUG_PRINT("[LKS] (sr_handle_arpreq) call send_arp_request.\n");
			send_arp_request(sr,req);
			req->sent = time(NULL);
			req->times_sent++;
		}
	}
	else{
		/* no timeout yet! do nothing. */
	}
	/* LKS end */
}

/* LKS start */
/* called by sr_handle_arpreq */
/* when we give up to send arp request broadcast */
/* we need to inform the sender */
void send_icmp_host_unreachable(struct sr_instance* sr, struct sr_arpreq* req){
	DEBUG_PRINT("[LKS] (send_icmp_host_unreachable) Sending ICMP Host Unreachable.\n");
	struct sr_packet* current_packet;
	current_packet = req->packets;
	while(current_packet){
		DEBUG_PRINT("[LKS] (send_icmp_host_unreachable) call sr_send_icmp.\n");
		sr_send_icmp(sr, current_packet->buf, current_packet->len, ICMP_UNREACHABLE_TYPE, ICMP_HOST_CODE);
		current_packet=current_packet->next;
	}
}

/* called by sr_handle_arpreq */
/* used to send an arp request broadcast */
void send_arp_request(struct sr_instance* sr, struct sr_arpreq* req){
	DEBUG_PRINT("[LKS] (send_arp_request) Sending ARP Request.\n"); 
	/* use broadcasting to find ip's owner. */
	struct sr_if *interface;
	sr_arp_hdr_t arp_header;
	/* sr_instance -> sr_arpreq -> sr_packet */
	interface = sr_get_interface(sr,req->packets->iface);
	arp_header.ar_hrd = htons(arp_hrd_ethernet); /* 1 */
	arp_header.ar_pro = htons(arp_pro_ip);		 /* 0x0800 */
	arp_header.ar_hln = ETHER_ADDR_LEN;			 /* 6 (define in sr_protocol) */
	arp_header.ar_pln = sizeof(uint32_t);		 /* 4 */
	arp_header.ar_op = htons(arp_op_request);	 /* 1 */
	memcpy(arp_header.ar_sha, interface->addr, ETHER_ADDR_LEN);
	arp_header.ar_sip = interface->ip;			 /* source ip */
	arp_header.ar_tip = req->ip;				 /* target ip */
	/* encapsulate and send packet */
	/* no need to send host unreachable */
	DEBUG_PRINT("[LKS] (send_arp_request) call make_eth_header.\n");
	sr_make_eth_header_and_send(sr, (uint8_t*) &arp_header, sizeof(arp_header), req->ip, ethertype_arp, 0);
}

/* LKS end */

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* TODO: (opt) Add initialization code here */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT free either (signified by "lent" comment).  
 * Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */){

  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  DEBUG_PRINT("[LKS] (sr_handlepacket) Received packet of length %d\n",len);
  /* printf("*** -> Received packet of length %d\n",len); */

  /* TODO: Add forwarding logic here */
	
	/* LKS start */
	/* sr_ethernet_hdr_t is needed */
	/* so if small than its size, this is a invalid packet. */
	if(len < sizeof(sr_ethernet_hdr_t)){
		DEBUG_PRINT("[LKS] (sr_handlepacket) Packet size < MINSIZE_PACKET, return.\n");
		return;
	}
	/* check type and process */
	if(ethertype(packet) == ethertype_arp) {
		DEBUG_PRINT("[LKS] (sr_handlepacket) This is a arp packet, call process_arp.\n");
		process_arp(sr,packet,len,interface);
	}
	else if(ethertype(packet) == ethertype_ip) {
		DEBUG_PRINT("[LKS] (sr_handlepacket) This is a ip packet, call process_ip.\n");
		process_ip(sr,packet,len,interface);
	}
	else{
		DEBUG_PRINT("[LKS] (sr_handlepacket) Invalid type %d.\n",ntohs(ethertype(packet)));
		DEBUG_PRINT("[LKS] (sr_handlepacket) This is a invalid type packet, return.\n");
		return;
	}
	/* LKS end */

}/* -- sr_handlepacket -- */

/* LKS start */
/* return 1 if valid otherwise return 0 */
int is_valid_ip_packet(uint8_t * packet, unsigned int len){
	sr_ip_hdr_t *ip_header;
	unsigned int ip_packet_len_of_packet;
	unsigned int ip_header_len;
	uint16_t ip_packet_len_in_packet;	/* uint16_t = unsigned short */
	uint16_t checksum_in_packet;
	uint16_t checksum_of_packet;
	
	/* sr_ethernet_hdr_t & sr_ip_hdr_t is needed */
	if(len < sizeof(sr_ip_hdr_t)+sizeof(sr_ethernet_hdr_t)){
		DEBUG_PRINT("[LKS] (is_valid_ip_packet) Packet size < MINSIZE_IP_PACKET.\n");
		return 0;
	}
	
	ip_header = get_ip_header(packet);
	/* check ip header size */
	ip_packet_len_of_packet = len - sizeof(sr_ethernet_hdr_t);
	ip_packet_len_in_packet = get_ip_packet_len(ip_header);
	ip_header_len = get_ip_header_len(ip_header); /* ip_header->ip_hl*4; */
	if(ip_packet_len_of_packet < ip_header_len){
		DEBUG_PRINT("[LKS] (is_valid_ip_packet) Packet's ip header size < %d.\n", ip_header_len);
		return 0;
	}
	/* check ip packet size */
	if(ip_packet_len_of_packet != ip_packet_len_in_packet){
		DEBUG_PRINT("[LKS] (is_valid_ip_packet) Packet's ip header size != %d.\n", ip_packet_len_in_packet); 
		return 0;
	}
	/* checksum */
	checksum_of_packet=0;
	checksum_in_packet=ip_header->ip_sum;
	/* set to 0 before cksum (cksum didn't included this.) */
	ip_header->ip_sum = 0;
	checksum_of_packet=cksum(ip_header,ip_header_len);
	if(checksum_in_packet != checksum_of_packet){
		DEBUG_PRINT("[LKS] (is_valid_ip_packet) Packet checksum failed.\n");
		return 0;
	}
	ip_header->ip_sum = checksum_in_packet;

	/* check ip version */
	if(ip_header->ip_v != ip_v4){
		DEBUG_PRINT("[LKS] This packet is not ipv4 packet.\n");
		return 0;
	}
	return 1;
}

void process_ip(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface){
	sr_ip_hdr_t *ip_header;
	
	/* check if valid */
	DEBUG_PRINT("[LKS] (process_ip) Processing ip packet...\n");
	if(!is_valid_ip_packet(packet, len)){
		DEBUG_PRINT("[LKS] (process_ip) Invalid ip packet so return.\n");
		return;
	}
	ip_header=get_ip_header(packet);
	
	#ifdef DEBUG
	struct in_addr src_ip_addr;
	struct in_addr dst_ip_addr;
	src_ip_addr.s_addr = ip_header->ip_src;
	dst_ip_addr.s_addr = ip_header->ip_dst;
	#endif
	DEBUG_PRINT("[LKS] (process_ip) %s->",inet_ntoa(src_ip_addr));
	DEBUG_PRINT("%s.\n",inet_ntoa(dst_ip_addr));
	
	if(!sr_interface_match_ip(sr,ip_header->ip_dst)){
		/* forward ip packet */	
		DEBUG_PRINT("[LKS] (process_ip) This ip packet is not for router, call forward_ip_packet.\n");
		forward_ip_packet(sr,ip_header);
	}
	else{
		/* this packet is for router */
		DEBUG_PRINT("[LKS] (process_ip) This ip packet is for router...\n");
		if(ip_header->ip_p==ip_protocol_icmp){
			DEBUG_PRINT("[LKS] (process_ip) This is a icmp packet, call process_icmp...\n");
			/* if icmp then process it maybe ping(echo request) */
			process_icmp(sr, ip_header);
		}
		else{
			/* if tcp/udp, udp=traceroute? */
			DEBUG_PRINT("[LKS] (process_ip) This is a UDP(traceroute?) packet, call sr_send_icmp.\n");
			sr_send_icmp(sr, (uint8_t*)ip_header, get_ip_packet_len(ip_header), ICMP_UNREACHABLE_TYPE, ICMP_PORT_CODE);
		}
	}
}

void forward_ip_packet(struct sr_instance* sr, sr_ip_hdr_t* ip_header){
	uint8_t* forward_ip_packet;
	unsigned int ip_packet_len;
	DEBUG_PRINT("[LKS] (forward_ip_packet) Forwarding ip packet...\n");
	ip_header->ip_ttl--;
	ip_packet_len = get_ip_packet_len(ip_header);

	/* recalculate checksum */
	/* maybe set to 0 before */
	ip_header->ip_sum = 0;
	ip_header->ip_sum = cksum(ip_header, get_ip_header_len(ip_header));

	#ifdef DEBUG
	struct in_addr src_ip_addr;
	struct in_addr dst_ip_addr;
	src_ip_addr.s_addr = ip_header->ip_src;
	dst_ip_addr.s_addr = ip_header->ip_dst;
	#endif
	DEBUG_PRINT("[LKS] (forward_ip_packet) %s->",inet_ntoa(src_ip_addr));
	DEBUG_PRINT("%s.\n",inet_ntoa(dst_ip_addr));

	if (ip_header->ip_ttl == 0) {
		DEBUG_PRINT("[LKS] (forward_ip_packet) TTL=0, send icmp time exceeded responce and return.\n");
		sr_send_icmp(sr, (uint8_t *)ip_header, ip_packet_len, ICMP_TIME_EXCEEDED_TYPE, 0);
		return;
	}
	/* make a copy */
	DEBUG_PRINT("[LKS] (forward_ip_packet) make a copy and call make_eth_header.\n");
	forward_ip_packet=malloc(ip_packet_len);
	memcpy(forward_ip_packet,ip_header,ip_packet_len);
	/* make a ethernet header */
	sr_make_eth_header_and_send(sr, forward_ip_packet, ip_packet_len, ip_header->ip_dst, ethertype_ip, 1);
	free(forward_ip_packet);
}

/* make a layer2(ethernet) header for layer3(arp,ip,icmp) packet */
void sr_make_eth_header_and_send(struct sr_instance* sr, uint8_t* packet, unsigned int len, uint32_t ip_dst, uint16_t type, int send_icmp){
	struct sr_rt* rt;
	struct sr_if* interface;
	struct sr_arpentry* arp_entry;
	unsigned int eth_packet_len;
	sr_ethernet_hdr_t eth_header;
	uint8_t* eth_packet;
	/* create arp req used */
	struct sr_arpreq *arp_req;

	DEBUG_PRINT("[LKS] (make_eth_header) Make ethernet header and send...\n");
	rt = sr_longest_prefix_match(sr, convert_to_in_addr(ip_dst));
	
	/* no routing entry found in routing table*/
	if(!rt){
		DEBUG_PRINT("[LKS] (make_eth_header) Cannot find routing entry using ip_dst...The dst cannot be arrived!\n");
		if(send_icmp){
			DEBUG_PRINT("[LKS] (make_eth_header) call sr_send_icmp.\n");
			sr_send_icmp(sr, packet, len, ICMP_UNREACHABLE_TYPE, ICMP_NET_CODE);
		}
		return;
	}
	DEBUG_PRINT("[LKS] (make_eth_header) Routing entry is found.\n");
	/* get interface */
	interface = sr_get_interface(sr, rt->interface);
	/* lookup arp cache and see whether the gateway is in cache */
	DEBUG_PRINT("[LKS] (make_eth_header) Looking for arp entry...\n");
	arp_entry = sr_arpcache_lookup(&sr->cache, rt->gw.s_addr);
	if (arp_entry || type == ethertype_arp) {
		eth_packet_len = len + sizeof(eth_header);
		/* ethernet header has 3 parameter */
		eth_header.ether_type = htons(type);
		/* Sending arp request from router is a broadcast work! */
		if(type==ethertype_arp && get_arp_op((sr_arp_hdr_t*)packet)==arp_op_request){
			DEBUG_PRINT("[LKS] (make_eth_header) This is a arp request for broadcasting.\n");
			memset(eth_header.ether_dhost,0xFF,ETHER_ADDR_LEN); /* FF:FF:FF:FF:FF:FF */
		}
		else{
			DEBUG_PRINT("[LKS] (make_eth_header) Arp entry is found and prepare sending to dst MAC.\n");
			memcpy(eth_header.ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);
		}
		memcpy(eth_header.ether_shost, interface->addr, ETHER_ADDR_LEN);
		/* malloc and copy header and layer3 packet in to that of mem */
		eth_packet = malloc(eth_packet_len);
		memcpy(eth_packet, &eth_header, sizeof(eth_header));
		memcpy(eth_packet+sizeof(eth_header), packet, len);
		/* sending packet */
		DEBUG_PRINT("[LKS] (make_eth_header) Sending the packet(eth_packet_len:%d)...\n",eth_packet_len);
		sr_send_packet(sr, eth_packet, eth_packet_len, rt->interface);
		free(eth_packet);

		/* arp_entry is alloc by sr_arpcache_lookup */
		if (arp_entry) free(arp_entry);
	}
	/* We can't find it so we need to do a arp request */
	/* We need to add it to queue and let it keep state and try several times */
	else{
		DEBUG_PRINT("[LKS] (make_eth_header) No arp entry found...Preparing the arp request.\n");
		eth_packet = malloc(len);
		memcpy(eth_packet, packet, len);
		/* add into queue */
		arp_req = sr_arpcache_queuereq(&sr->cache, rt->gw.s_addr, eth_packet, len, rt->interface);
		sr_handle_arpreq(sr, arp_req);
		free(eth_packet);	
	}
} 

void sr_send_icmp(struct sr_instance* sr, uint8_t *packet, unsigned int len, uint8_t type, uint8_t code){
	sr_icmp_hdr_t icmp_header;
	sr_icmp_hdr_t* icmp_header_ptr;
	sr_ip_hdr_t* error_ip_header_ptr;
	sr_ip_hdr_t ip_header;
	struct sr_rt* rt;
	struct sr_if* interface;
	uint16_t icmp_len; 
	uint16_t total_len;
	uint8_t* new_ip_packet;
	uint8_t* new_ip_packet_ptr;
	uint32_t ip_dst;

	/*
		ICMP error messages contain a data section that includes the entire IPv4 header, plus the first eight bytes of data from the IPv4 packet that caused the error message. The ICMP packet is then encapsulated in a new IPv4 packet.
	*/

	/* DEBUG_PRINT("[LKS] (sr_send_icmp) Sending ICMP packet TYPE:%d, CODE:%d...\n",type,code); */
	
	if (type == ICMP_UNREACHABLE_TYPE || type == ICMP_TIME_EXCEEDED_TYPE) {
		
		#ifdef DEBUG
		if(type == ICMP_UNREACHABLE_TYPE){
			if(code == ICMP_PORT_CODE)
				DEBUG_PRINT("[LKS] (sr_send_icmp) Making a port unreachable icmp packet.\n");
			else if(code == ICMP_HOST_CODE)
				DEBUG_PRINT("[LKS] (sr_send_icmp) Making a host unreachable icmp packet.\n");
			else if(code == ICMP_NET_CODE)
				DEBUG_PRINT("[LKS] (sr_send_icmp) Making a net unreachable icmp packet.\n");
		}
		else
			DEBUG_PRINT("[LKS] (sr_send_icmp) Making a TTL=0 icmp packet.\n");
		#endif

		error_ip_header_ptr = (sr_ip_hdr_t*) packet;
		/* check if dst is reachable. */
		rt = sr_longest_prefix_match(sr, convert_to_in_addr(error_ip_header_ptr->ip_src));
		if(!rt){
			DEBUG_PRINT("[LKS] (sr_send_icmp) the ip_src is a ip which is not reachable, return.\n");
			return;	
		}
		interface = sr_get_interface(sr, rt->interface);

		/* fill icmp field */
		icmp_header.icmp_type = type;
		icmp_header.icmp_code = code;
		icmp_header.icmp_sum = 0; /* will be updated */
		icmp_header.unused = 0; /* unused field */

		/* fill ip field */
		ip_header.ip_hl = MIN_IP_HDR_LEN>>2; /* 20>>2=5 */
		ip_header.ip_v = ip_v4;				 /* 4 */
		ip_header.ip_tos = 0;
		ip_header.ip_len = 0; 				 /* will be updated */
		ip_header.ip_id = error_ip_header_ptr->ip_id;
		ip_header.ip_off = htons(IP_DF);	 /* Don't Fragment */
		ip_header.ip_ttl = DEFAULT_TTL;
		ip_header.ip_p = ip_protocol_icmp;
		ip_header.ip_sum = 0;				 /* will be updated */
		/* the ip_src should be the outgoing interface's ip address */
		ip_header.ip_src = interface->ip;
		ip_header.ip_dst = error_ip_header_ptr->ip_src; 
		ip_dst = ip_header.ip_dst;
		
		#ifdef DEBUG
		struct in_addr src_ip_addr;
		struct in_addr dst_ip_addr;
		src_ip_addr.s_addr = error_ip_header_ptr->ip_src;
		dst_ip_addr.s_addr = error_ip_header_ptr->ip_dst;
		#endif
		DEBUG_PRINT("[LKS] (sr_send_icmp) ori %s->",inet_ntoa(src_ip_addr));
		DEBUG_PRINT("%s.\n",inet_ntoa(dst_ip_addr));	
		
		/* calculate total_len and update ip_header.ip_len */
		/* [ip_header[icmp_header|error_ip_header|8 bytes]] */
		icmp_len = sizeof(icmp_header)+ get_ip_header_len(error_ip_header_ptr) + 8;
		total_len = icmp_len + MIN_IP_HDR_LEN;
		ip_header.ip_len = htons(total_len);
		
		/* checksum */
		ip_header.ip_sum = cksum(&ip_header,MIN_IP_HDR_LEN);
		
		/* make a copy */
		new_ip_packet = malloc(total_len);	
		new_ip_packet_ptr = new_ip_packet;
		/* ip_header */
		memcpy(new_ip_packet_ptr,&ip_header,MIN_IP_HDR_LEN);
		new_ip_packet_ptr+=MIN_IP_HDR_LEN;
		/* icmp header */
		memcpy(new_ip_packet_ptr,&icmp_header,sizeof(icmp_header));
		new_ip_packet_ptr+=sizeof(icmp_header);
		/* rest 8 bytes */
		memcpy(new_ip_packet_ptr,error_ip_header_ptr,get_ip_header_len(error_ip_header_ptr) + 8);
	}
	else if (type == ICMP_ECHO_REPLY_TYPE) {
		error_ip_header_ptr = (sr_ip_hdr_t*) packet;
		/* We are required to reply this icmp packet. */
		/* Just modify something and resend it */
		DEBUG_PRINT("[LKS] (sr_send_icmp) Making a echo reply packet.\n");
		ip_dst = error_ip_header_ptr->ip_src;
		error_ip_header_ptr->ip_src = error_ip_header_ptr->ip_dst;
		error_ip_header_ptr->ip_dst = ip_dst;

		/* modify data in icmp packet */
		icmp_header_ptr = get_icmp_header(error_ip_header_ptr);
		/*
		DEBUG_PRINT("[LKS] (sr_send_icmp) type=%d, code=%d.\n",icmp_header_ptr->icmp_type,icmp_header_ptr->icmp_code);
		*/
		icmp_header_ptr->icmp_type = type;
		icmp_header_ptr->icmp_code = code;
		icmp_header_ptr->icmp_sum = 0;
		
		/* make a copy */
		total_len = get_ip_packet_len(error_ip_header_ptr);
		icmp_len = total_len - MIN_IP_HDR_LEN;
		new_ip_packet = malloc(total_len);
		memcpy(new_ip_packet,error_ip_header_ptr,total_len);
	}

	/* checksum icmp */
	/* [ip_header[icmp_header|error_ip_header|8byte]] */
	/* checksum for [icmp_header|error_ip_header|8byte] */
	icmp_header_ptr = get_icmp_header((sr_ip_hdr_t*)new_ip_packet);
	icmp_header_ptr->icmp_sum = cksum(icmp_header_ptr,icmp_len);
	DEBUG_PRINT("[LKS] (sr_send_icmp) type=%d, code=%d.\n",icmp_header_ptr->icmp_type,icmp_header_ptr->icmp_code);
	DEBUG_PRINT("[LKS] (sr_send_icmp) ip_packet_len=%d.\n",get_ip_packet_len((sr_ip_hdr_t*)new_ip_packet));

	#ifdef DEBUG
	struct in_addr src_ip_addr;
	struct in_addr dst_ip_addr;
	src_ip_addr.s_addr = ip_header.ip_src;
	dst_ip_addr.s_addr = ip_header.ip_dst;
	#endif
	DEBUG_PRINT("[LKS] (sr_send_icmp) %s->",inet_ntoa(src_ip_addr));
	DEBUG_PRINT("%s.\n",inet_ntoa(dst_ip_addr));
	
	/* make eth header and send ip packet */
	DEBUG_PRINT("[LKS] (sr_send_icmp) Calling make_eth_header(total_len:%d).\n",total_len);
	sr_make_eth_header_and_send(sr, new_ip_packet, total_len, ip_dst, ethertype_ip, 0);	
	free(new_ip_packet);
}

void process_icmp(struct sr_instance* sr, sr_ip_hdr_t* ip_header){
	DEBUG_PRINT("[LKS] (process_icmp) Check if valid icmp packet.\n");
	if (!is_valid_icmp_packet(ip_header)){
		DEBUG_PRINT("[LKS] (process_icmp) This is a invalid icmp packet, return.\n");
		return;
	}
	DEBUG_PRINT("[LKS] (process_icmp) Calling sr_send_icmp.\n");
	sr_send_icmp(sr, (uint8_t *)ip_header, get_ip_packet_len(ip_header), ICMP_ECHO_REPLY_TYPE, ICMP_ECHO_CODE);
}

int is_valid_icmp_packet(sr_ip_hdr_t* ip_header){
	sr_icmp_hdr_t* icmp_header;
	uint16_t checksum_in_packet;
	uint16_t checksum_of_packet;
	unsigned int icmp_len;

	icmp_header = get_icmp_header(ip_header);
	icmp_len = get_ip_packet_len(ip_header)-get_ip_header_len(ip_header);
	checksum_in_packet = icmp_header->icmp_sum;
	/* set to 0 before cksum (cksum didn't included this.) */  
	icmp_header->icmp_sum = 0;
	checksum_of_packet = cksum(icmp_header,icmp_len);
	if(checksum_in_packet!=checksum_of_packet){
		DEBUG_PRINT("[LKS] (is_valid_icmp_packet) checksum failed, return!\n");
		return 0;
	}
	icmp_header->icmp_sum = checksum_in_packet;

	/* make sure this is a echo request */
	if ((icmp_header->icmp_type != ICMP_ECHO_REQUEST_TYPE) || (icmp_header->icmp_code != ICMP_ECHO_CODE)){
		DEBUG_PRINT("[LKS] (is_valid_icmp_packet) Invalid type!\n");
		return 0;
	}

	return 1;
}

void process_arp(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface){
	struct sr_if* rec_interface;
	sr_arp_hdr_t* arp_header;
	struct sr_arpentry* arp_entry;
	struct sr_arpreq* arp_req; 
	/* check if valid */
	if (!is_valid_arp_packet(packet, len)){
		DEBUG_PRINT("[LKS] (process_arp) This is an invalid arp packet, return!\n");
		return;
	}
	/* get interface struct */
	rec_interface=sr_get_interface(sr,interface);
	/* get arp header ptr */
	arp_header = get_arp_header(packet);
	if(rec_interface->ip!=arp_header->ar_tip){
		DEBUG_PRINT("[LKS] (process_arp) This arp packet is not for router.\n");
		return;
	}
	
	/* check if exist in cache */
	arp_entry=sr_arpcache_lookup(&sr->cache,arp_header->ar_sip);
	if(arp_entry){
		DEBUG_PRINT("[LKS] (process_arp) SourceIP's mapping is existed in arp cache.\n");
		free(arp_entry);	
	}
	else{
		DEBUG_PRINT("[LKS] (process_arp) Add mapping into arp cache.\n");
		arp_req = sr_arpcache_insert(&sr->cache, arp_header->ar_sha, arp_header->ar_sip);
		if(arp_req){
			DEBUG_PRINT("[LKS] (process_arp) Send all waiting packet of this ip.\n");
			sr_arpreq_send_all_packets(sr,arp_req);
			sr_arpreq_destroy(&sr->cache,arp_req);
		}
	}

	if (get_arp_op(arp_header) == arp_op_request) {
		DEBUG_PRINT("[LKS] (process_arp) This is a arp request ask for router MAC.\n");
		process_arp_request(sr, arp_header, rec_interface);
	}
}

int is_valid_arp_packet(uint8_t* packet, unsigned int len){
	sr_arp_hdr_t* arp_header;
	
	/* [ethernet|arp] */
	if(len < sizeof(sr_arp_hdr_t)+sizeof(sr_ethernet_hdr_t)){
		DEBUG_PRINT("[LKS] (is_valid_arp_packet) Packet size < MINSIZE_ARP_PACKET.\n");
		return 0;
	}
	arp_header = get_arp_header(packet);
	if(get_arp_hrd(arp_header)!=arp_hrd_ethernet){
		DEBUG_PRINT("[LKS] (is_valid_arp_packet) Invalid Packet(not mac).\n");
		return 0;
	}
	if(get_arp_pro(arp_header)!=arp_pro_ip){
		DEBUG_PRINT("[LKS] (is_valid_arp_packet) Invalid Packet(not ip).\n");
		return 0;
	}
	return 1;
}

void process_arp_request(struct sr_instance* sr, sr_arp_hdr_t* arp_header, struct sr_if* interface){
	sr_arp_hdr_t reply_arp_header;
	DEBUG_PRINT("[LKS] (process_arp_request) Reply it with router MAC.\n");
	/* make a arp packet */
	reply_arp_header.ar_hrd = htons(arp_hrd_ethernet); /* 1 */ 
	reply_arp_header.ar_pro = htons(arp_pro_ip);       /* 0x0800 */
	reply_arp_header.ar_hln = ETHER_ADDR_LEN;          /* 6 (define in sr_protocol) */
	reply_arp_header.ar_pln = sizeof(uint32_t);        /* 4 */
	reply_arp_header.ar_op = htons(arp_op_reply);
	memcpy(reply_arp_header.ar_sha, interface->addr, ETHER_ADDR_LEN);
	reply_arp_header.ar_sip = interface->ip;
	memcpy(reply_arp_header.ar_tha, arp_header->ar_sha, ETHER_ADDR_LEN);
	reply_arp_header.ar_tip = arp_header->ar_sip;
	DEBUG_PRINT("[LKS] (process_arp_request) call make_eth_header.\n");
	sr_make_eth_header_and_send(sr, (uint8_t*) &reply_arp_header, sizeof(reply_arp_header), arp_header->ar_sip, ethertype_arp, 1);
}

void sr_arpreq_send_all_packets(struct sr_instance* sr, struct sr_arpreq* req){
	DEBUG_PRINT("[LKS] (sr_arpreq_send_all_packets) Sending ip packets to a just knowning MAC.\n");
	struct sr_packet* current;
	sr_ip_hdr_t* ip_header;
	current = req->packets;
	/* forward_ip_packet(ttl-- already) -> not found arp entry in cache */
	/* -> sr_arpcache_queuereq */
	/* now, the arp entry is found, we need to resend it */
	while(current){
		ip_header = (sr_ip_hdr_t*) current->buf;
		sr_make_eth_header_and_send(sr, current->buf, current->len, ip_header->ip_dst, ethertype_ip, 1);
		current = current->next;
	}
}

/* LKS end */
