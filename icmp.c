#include "icmp.h"
#include "ip.h"
#include "rtable.h"
#include "arp.h"
#include "base.h"
#include "packet.h"
#include "arpcache.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>

#define ICMP_COPY_SIZE 1
// send icmp packet: construct icmp packet and send the packet by ip_send_packet
void icmp_send_packet(const char *in_pkt, int len, u8 type, u8 code)
{
	char* icmp_packet;
	struct iphdr *temp_ip_header = (struct iphdr *)(in_pkt + ETHER_HDR_SIZE);
	icmp_packet = malloc(len);
	struct ether_header *eth_header = (struct ether_header *)icmp_packet;
	struct iphdr *ip_header=(struct iphdr *)(icmp_packet+ETHER_HDR_SIZE);
	struct icmphdr *icmpheader =(struct icmphdr *)(icmp_packet+ETHER_HDR_SIZE+IP_BASE_HDR_SIZE);
	//设置ethernet header
    struct ether_header *packet_header = (struct ether_header *)in_pkt;
    eth_header->ether_type=htons(ETH_P_IP);
    memcpy(eth_header->ether_dhost,packet_header->ether_shost,ETH_ALEN);
    memcpy(eth_header->ether_shost,packet_header->ether_dhost,ETH_ALEN);
	//设置ip header
	struct iphdr *packet_ip_header =(struct iphdr *)(in_pkt+ETHER_HDR_SIZE);
	u32 temp_ntohl_daddr=ntohl(packet_ip_header->daddr);
	u32 temp_ntohl_saddr=ntohl(packet_ip_header->saddr);
	ip_init_hdr(ip_header,temp_ntohl_daddr,temp_ntohl_saddr,len-ETHER_HDR_SIZE,IPPROTO_ICMP);

	if(type == 3&&code==0)//路由表查找失败
	{	
		//设置icmp头部
		icmpheader->type=3;
		icmpheader->code=0;
		icmpheader->checksum=icmp_checksum(icmpheader,ICMP_HDR_SIZE+ICMP_COPIED_DATA_LEN);
		icmpheader->icmp_identifier=0;//前四位设为0
		icmpheader->icmp_sequence=0;
		//设置Rest of Header
		memcpy(icmpheader+ICMP_HDR_SIZE,packet_ip_header,IP_HDR_SIZE(temp_ip_header)+ICMP_COPIED_DATA_LEN);
	}
	if(type == 3&&code==1)//ARP查询失败
	{	
		//设置icmp头部
		icmpheader->type=3;
		icmpheader->code=1;
		icmpheader->checksum=icmp_checksum(icmpheader,ICMP_HDR_SIZE+ICMP_COPIED_DATA_LEN);
		icmpheader->icmp_identifier=0;
		icmpheader->icmp_sequence=0;
		//设置Rest of Header
		memcpy(icmpheader+ICMP_HDR_SIZE,packet_ip_header,IP_HDR_SIZE(temp_ip_header)+ICMP_COPIED_DATA_LEN);
	}
	if(type ==11&&code==0)//TTL值为0
	{
		//设置icmp头部
		icmpheader->type=11;
		icmpheader->code=0;
		icmpheader->checksum=icmp_checksum(icmpheader,ICMP_HDR_SIZE+ICMP_COPIED_DATA_LEN);
		icmpheader->icmp_identifier=0;
		icmpheader->icmp_sequence=0;
		//设置Rest of Header
		memcpy(icmpheader+ICMP_HDR_SIZE,packet_ip_header,IP_HDR_SIZE(temp_ip_header)+ICMP_COPIED_DATA_LEN);
	}
	if(type == 0&&code==0)//Ping本端口
	{
		//设置icmp头部
		struct icmphdr *temp_icmp_header = (struct icmphdr *)(in_pkt + ETHER_HDR_SIZE+IP_BASE_HDR_SIZE);
		icmpheader->type=0;
		icmpheader->code=0;
		icmpheader->icmp_identifier=temp_icmp_header->icmp_identifier;
		icmpheader->icmp_sequence=temp_icmp_header->icmp_sequence;
		
		memcpy(icmpheader+ICMP_COPY_SIZE,temp_icmp_header+ICMP_COPY_SIZE,len-ETHER_HDR_SIZE-IP_BASE_HDR_SIZE-8);
		//设置Rest of Header
		icmpheader->checksum=icmp_checksum(icmpheader,len-ETHER_HDR_SIZE-IP_BASE_HDR_SIZE);
	}
	ip_send_packet(icmp_packet, len);
	return NULL;
}
