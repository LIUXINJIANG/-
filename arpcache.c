#include "arpcache.h"
#include "arp.h"
#include "ether.h"
#include "packet.h"
#include "icmp.h"
#include "ip.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include "rtable.h"

static arpcache_t arpcache;

// lookup the IP->mac mapping
//
// traverse the hash table to find whether there is an entry with the same IP
// and mac address with the given arguments
int arpcache_lookup(u32 ip4, u8 mac[ETH_ALEN])
{
	int found = 0;
	int i=0;
	struct arp_cache_entry find_arp;
	pthread_mutex_lock(&(arpcache.lock));
	for (i=0;i<32;i++)
	{
		find_arp =arpcache.entries[i];
		if(find_arp.ip4 == ip4&&find_arp.valid==1)
		{
			found=1;
			memcpy(mac,find_arp.mac,ETH_ALEN);
		}
	}
	pthread_mutex_unlock(&(arpcache.lock));
	return found;
}

// append the packet to arpcache
//
// Lookup in the hash table which stores pending packets, if there is already an
// entry with the same IP address and iface (which means the corresponding arp
// request has been sent out), just append this packet at the tail of that entry
// (the entry may contain more than one packet); otherwise, malloc a new entry
// with the given IP address and iface, append the packet, and send arp request.
void arpcache_append_packet(iface_info_t *iface, u32 ip4, char *packet, int len)
{
		struct arp_req *pos=NULL,*q;
		if (list_empty(&(arpcache.req_list))) {
		struct arp_req *req_ip = malloc(sizeof(struct arp_req));
		req_ip->iface = iface;
		req_ip->ip4 = ip4;
		time(&req_ip->sent);
		req_ip->retries = 1;
		struct cached_pkt *req_ip_packet = malloc(sizeof(struct cached_pkt));
		req_ip_packet->packet = packet;
		req_ip_packet->len = len;
		init_list_head(&req_ip->cached_packets);
		list_add_tail(&req_ip_packet->list,&req_ip->cached_packets);
		pthread_mutex_lock(&(arpcache.lock));
		list_add_tail(&req_ip->list,&(arpcache.req_list));
		pthread_mutex_unlock(&(arpcache.lock));
		arp_send_request(iface,ip4);
	}
	else
	{
		list_for_each_entry_safe(pos,q,&(arpcache.req_list),list)
		{
			if (pos->ip4 == ip4)
			{
				if (pos->iface->ip == iface->ip)     
				{
					struct cached_pkt *req_ip_packet = malloc(sizeof(struct cached_pkt));
					req_ip_packet->packet = packet;
					req_ip_packet->len = len;
					pthread_mutex_lock(&(arpcache.lock));
					list_add_tail(&req_ip_packet->list, &pos->cached_packets);
					pthread_mutex_unlock(&(arpcache.lock));
					return NULL;
				}
			}
		}
		struct arp_req *req_ip = malloc(sizeof(struct arp_req));
		req_ip->iface = iface;
		req_ip->ip4 = ip4;
		time(&req_ip->sent);
		req_ip->retries = 1;
		struct cached_pkt *req_ip_packet = malloc(sizeof(struct cached_pkt));
		req_ip_packet->packet = packet;
		req_ip_packet->len = len;
		init_list_head(&req_ip->cached_packets);
		pthread_mutex_lock(&(arpcache.lock));
		list_add_tail(&req_ip_packet->list,&req_ip->cached_packets);
		list_add_tail(&req_ip->list,&(arpcache.req_list));
		pthread_mutex_unlock(&(arpcache.lock));
		arp_send_request(iface,ip4);
	}
	return NULL;
}

// insert the IP->mac mapping into arpcache, if there are pending packets
// waiting for this mapping, fill the ethernet header for each of them, and send
// them out
void arpcache_insert(u32 ip4, u8 mac[ETH_ALEN])
{
	int find=0;
	int i=0;
	while(find==0){
		if((arpcache.entries[i]).ip4 == 0){
			pthread_mutex_lock(&(arpcache.lock));
			(arpcache.entries[i]).ip4 = ip4;
			memcpy((arpcache.entries[i]).mac,mac,ETH_ALEN);
			time((arpcache.entries[i]).added);
			(arpcache.entries[i]).valid = 1;
			pthread_mutex_unlock(&(arpcache.lock));
			find=1;
		}
		i++;
		if(i==32) find=-1;
	}
	if(find==-1){
		int index =rand()%32;
		pthread_mutex_lock(&(arpcache.lock));
		(arpcache.entries[index]).ip4 = ip4;
		memcpy((arpcache.entries[index]).mac,mac,ETH_ALEN);
		time((arpcache.entries[index]).added);
		(arpcache.entries[index]).valid = 1;
		pthread_mutex_unlock(&(arpcache.lock));
	}
	struct arp_req *pos,*q;
	list_for_each_entry_safe(pos,q,&(arpcache.req_list),list){
		if(pos->ip4==ip4){
			if(!list_empty(&(pos->cached_packets)))
			{
				struct cached_pkt *req_ip_packet,*p;
				pthread_mutex_lock(&(arpcache.lock));
				list_for_each_entry_safe(req_ip_packet,p,&(pos->cached_packets),list)
				{

					struct ether_header *header =(struct ether_header *)(req_ip_packet->packet);
				
					memcpy(header->ether_dhost,mac,ETH_ALEN);
					
			
					size_t plen = sizeof(req_ip_packet->packet);
					iface_send_packet(pos->iface,req_ip_packet->packet,req_ip_packet->len);
					list_delete_entry(&(req_ip_packet->list));
					free(req_ip_packet);
				}
				pthread_mutex_unlock(&(arpcache.lock));
			}
			pthread_mutex_lock(&(arpcache.lock));
			list_delete_entry(&(pos->list));
			free(pos);
			pthread_mutex_unlock(&(arpcache.lock));
		}

	}
}

// sweep arpcache periodically
//
// For the IP->mac entry, if the entry has been in the table for more than 15
// seconds, remove it from the table.
// For the pending packets, if the arp request is sent out 1 second ago, while 
// the reply has not been received, retransmit the arp request. If the arp
// request has been sent 5 times without receiving arp reply, for each
// pending packet, send icmp packet (DEST_HOST_UNREACHABLE), and drop these
// packets.
void *arpcache_sweep(void *arg) 
{

	while(1){
		int i;
		pthread_mutex_lock(&(arpcache.lock));			//lock the arpcache
		time_t nowtime = time((time_t*)NULL);
		for (i=0;i<32;i++){
			if(nowtime-(arpcache.entries[i]).added>15){		//if the arpcache_entry added time > 15 remove it.
				memset(&(arpcache.entries[i]),0, sizeof(struct arp_cache_entry));	//remove it
			}
		}
		
		struct arp_req *pos,*q;
		nowtime = time((time_t*)NULL);
		list_for_each_entry_safe(pos,q,&(arpcache.req_list),list){
			if(nowtime-pos->sent>1&&pos->retries<6){
				iface_info_t *iface = pos->iface;
				u32 ip4 = pos->ip4;
				arp_send_request(iface,ip4);
				pos->sent= nowtime;
				pos->retries +=1;
			}else if(pos->retries>5){
				struct cached_pkt *req_ip_packet,*n;
				list_for_each_entry_safe(req_ip_packet,n,&(pos->cached_packets),list){
					icmp_send_packet(req_ip_packet->packet,req_ip_packet->len,ICMP_DEST_UNREACH,ICMP_HOST_UNREACH);
				}

			}
		}
		pthread_mutex_unlock(&(arpcache.lock));	
		sleep(1);
	}

}

// initialize IP->mac mapping, request list, lock and sweeping thread
void arpcache_init()
{
	bzero(&arpcache, sizeof(arpcache_t));
	init_list_head(&(arpcache.req_list));
	pthread_mutex_init(&arpcache.lock, NULL);
	pthread_create(&arpcache.thread, NULL, arpcache_sweep, NULL);
}

// release all the resources when exiting
void arpcache_destroy()
{
	pthread_mutex_lock(&arpcache.lock);

	struct arp_req *req_entry = NULL, *req_q;
	list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
		struct cached_pkt *pkt_entry = NULL, *pkt_q;
		list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list) {
			list_delete_entry(&(pkt_entry->list));
			free(pkt_entry->packet);
			free(pkt_entry);
		}

		list_delete_entry(&(req_entry->list));
		free(req_entry);
	}

	pthread_kill(arpcache.thread, SIGTERM);

	pthread_mutex_unlock(&arpcache.lock);
}


