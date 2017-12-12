#include "arp.h"
#include "base.h"
#include "types.h"
#include "packet.h"
#include "ether.h"
#include "arpcache.h"

#include <stdlib.h>
#include <string.h>

#include "log.h"

#include "ip.h"
#include "icmp.h"
#include "rtable.h"

struct package_header {
	struct ether_header *eheader;
	struct ether_arp *earp;
};

// send an arp request: encapsulate an arp request packet, send it out through
// iface_send_packet
void arp_send_request(iface_info_t *iface, u32 dst_ip)
{
	size_t packet_size = ETHER_HDR_SIZE+sizeof(struct ether_arp);//定义包的大小
	char *packet= malloc(packet_size);//给包空间
	struct ether_header *header = (struct ether_header *)packet;//转化成mac头包
	struct ether_arp *arp= (struct ether_arp*)(packet+ETHER_HDR_SIZE);//arp包的大小
	header->ether_type=htons(ETH_P_ARP);//类型定义
	memset(header->ether_dhost,0xff,ETH_ALEN);//将后面的字节用ff代替
	memcpy(header->ether_shost,iface->mac,ETH_ALEN);//接口地址给目的mac地址
	arp->arp_hrd=htons(0x01);
	arp->arp_pro=htons(0x0800);
	arp->arp_hln=6;
	arp->arp_pln=4;
	arp->arp_op=htons(ARPOP_REQUEST);
	arp->arp_spa=htonl(iface->ip);
	arp->arp_tpa=htonl(dst_ip);
	memset(arp->arp_tha,0,ETH_ALEN);
	memcpy(arp->arp_sha,iface->mac,ETH_ALEN);

	iface_send_packet(iface,packet,packet_size);

}

// send an arp reply packet: encapsulate an arp reply packet, send it out
// through iface_send_packet
void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr)
{
	size_t packet_size = ETHER_HDR_SIZE+sizeof(struct ether_arp);
	char *packet= malloc(packet_size);
	struct ether_header *header = (struct ether_header *)packet;
	struct ether_arp *arp= (struct ether_arp*)(packet+sizeof(struct ether_header));
	header->ether_type=htons(ETH_P_ARP);
	header->ether_type=htons(ETH_P_ARP);
	memcpy(header->ether_dhost,req_hdr->arp_sha,ETH_ALEN);
	memcpy(header->ether_shost,iface->mac,ETH_ALEN);
	arp->arp_hrd=htons(0x01);
	arp->arp_pro=htons(0x0800);
	arp->arp_hln=6;
	arp->arp_pln=4;
	arp->arp_op=htons(ARPOP_REPLY);
	arp->arp_spa=htonl(iface->ip);
	arp->arp_tpa=htonl(req_hdr->arp_spa);
	memcpy(arp->arp_sha,iface->mac,ETH_ALEN);
	memcpy(arp->arp_tha,req_hdr->arp_sha,ETH_ALEN);
	iface_send_packet(iface,packet, packet_size);
}

// handle arp packet: 
//
// 1. If the dest ip address of this arp packet is not equal to the ip address 
//    of the incoming iface, drop it. 
// 2. If it is an arp request packet, send arp reply to the destination, insert 
//    the ip->mac mapping into arpcache.
// 3. If it is an arp reply packet, insert the ip->mac mapping into arpcache.
void handle_arp_packet(iface_info_t *iface, char *packet, int len)
{
	struct ether_arp *arp = packet_to_ether_arp(packet);
	u32 src_ip = ntohl(arp->arp_spa),	
		dst_ip = ntohl(arp->arp_tpa);	
	if (iface->ip == dst_ip) {
		if (ntohs(arp->arp_op) == ARPOP_REQUEST) {	//If it is an arp request packet, 
			arp_send_reply(iface, arp);				//send arp reply to the destination
			arpcache_insert(src_ip, arp->arp_sha);	//insert the ip->mac mapping into arpcache.
		} else if (ntohs(arp->arp_op) == ARPOP_REPLY) {//If it is an arp reply packet
			// cache this arp entry.
			arpcache_insert(src_ip, arp->arp_sha);	//insert the ip->mac mapping into arpcache.
		}
	}

	free(packet);
}

// send (IP) packet through arpcache lookup 
//
// Lookup the mac address of dst_ip in arpcache. If it is found, fill the
// ethernet header and emit the packet by iface_send_packet, otherwise, pending 
// this packet into arpcache, and send arp request.
void iface_send_packet_by_arp(iface_info_t *iface, u32 dst_ip, char *packet, int len)
{
	struct ether_header *eh = (struct ether_header *)packet;

	eh->ether_type = ntohs(ETH_P_IP);

	u8 dst_mac[ETH_ALEN];
	int found = arpcache_lookup(dst_ip, dst_mac);
	if (found) {
		memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
		memcpy(eh->ether_dhost, dst_mac, ETH_ALEN);
		iface_send_packet(iface, packet, len);
	}
	else {
		arpcache_append_packet(iface, dst_ip, packet, len);
	}
}



