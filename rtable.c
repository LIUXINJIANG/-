#include "rtable.h"

#include "log.h"

#include <stdlib.h>
#include <unistd.h>

#include <net/if.h>
#include <net/route.h>
#include <sys/ioctl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#define ROUTE_BATCH_SIZE 10240

// XXX: All the functions in this file should be treated as a blackbox. You do not 
// need to understand how it works, but only trust it will process like the function
// name indicates.

struct list_head rtable;

// Structure for sending the request for routing table
typedef struct {
	struct nlmsghdr nlmsg_hdr;
	struct rtmsg rt_msg;
	char buf[ROUTE_BATCH_SIZE];
} route_request;

static void if_index_to_name(int if_index, char *if_name)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0); 
	if (fd == -1) {
		perror("Create socket failed.");
		exit(-1);
	}

	struct ifreq ifr;
	ifr.ifr_ifindex = if_index;

	if (ioctl(fd, SIOCGIFNAME, &ifr, sizeof(ifr))) {
		perror("Get interface name failed.");
		exit(-1);
	}

	strcpy(if_name, ifr.ifr_name);
}

static iface_info_t *if_name_to_iface(const char *if_name)
{
	iface_info_t *iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		if (strcmp(iface->name, if_name) == 0)
			return iface;
	}

	fprintf(stderr, "Could not find the desired interface "
			"according to if_name '%s'\n", if_name);
	return NULL;
}

static int get_unparsed_route_info(char *buf, int size)
{
	int fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE); 

	route_request *req = (route_request *)malloc(sizeof(route_request));
	bzero(req,sizeof(route_request));
	req->nlmsg_hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	req->nlmsg_hdr.nlmsg_type = RTM_GETROUTE;
	req->nlmsg_hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	req->rt_msg.rtm_family = AF_INET;
	req->rt_msg.rtm_table = 254; 

	if ((send(fd, req, sizeof(route_request), 0)) < 0) {
		perror("Send routing request failed.");
		exit(-1);
	}

	int len = 0;
	int left = size;
	while (1) {
		if (left < sizeof(struct nlmsghdr)) {
			fprintf(stderr, "Routing table is larger than %d.\n", size);
			exit(-1);
		}

		int nbytes = recv(fd, buf + len, left, 0);
		if (nbytes < 0) {
			fprintf(stderr, "Receive routing info failed.\n");
			break;
		} else if (nbytes == 0) {
			fprintf(stdout, "EOF in netlink\n");
			break;
		}

		struct nlmsghdr *nlp = (struct nlmsghdr*)(buf+len);
		if (nlp->nlmsg_type == NLMSG_DONE) {
			break;
		} else if (nlp->nlmsg_type == NLMSG_ERROR) {
			fprintf(stderr, "Error exists in netlink msg.\n");
			exit(-1);
		}

		len += nbytes;
		left -= nbytes;
	}

	close(fd);

	return len;
}

static int parse_routing_info(char *buf, int len)
{
	int n = 0;
	init_list_head(&rtable);

	// Outer loop: Iterate all the NETLINK headers
	rt_entry_t tmp_entry;
	for (struct nlmsghdr *nlp = (struct nlmsghdr *)buf;
			NLMSG_OK(nlp, len); nlp = NLMSG_NEXT(nlp, len)) {
		// get route entry header
		struct rtmsg *rtp = (struct rtmsg *)NLMSG_DATA(nlp);
		// we only care about the tableId route table
		if (rtp->rtm_table != 254)
			continue;

		bzero(&tmp_entry, sizeof(rt_entry_t));
		// tmp_entry.proto = rtp->rtm_protocol;

		// Inner loop: iterate all the attributes of one route entry
		struct rtattr *rtap = (struct rtattr *)RTM_RTA(rtp);
		int rtl = RTM_PAYLOAD(nlp);
		for (; RTA_OK(rtap, rtl); rtap = RTA_NEXT(rtap, rtl)) {
			switch(rtap->rta_type)
			{
				// destination IPv4 address
				case RTA_DST:
					tmp_entry.dest = ntohl(*(u32 *)RTA_DATA(rtap));
					tmp_entry.mask = 0xFFFFFFFF << (32 - rtp->rtm_dst_len);
					break;
				case RTA_GATEWAY:
					tmp_entry.gw = ntohl(*(u32 *)RTA_DATA(rtap));
					break;
				case RTA_PREFSRC:
					// tmp_entry.addr = *(u32 *)RTA_DATA(rtap);
					break;
				case RTA_OIF:
					if_index_to_name(*((int *) RTA_DATA(rtap)), tmp_entry.if_name);
					break;
				default:
					break;
			}
		}

		tmp_entry.flags |= RTF_UP;
		if (tmp_entry.gw != 0)
			tmp_entry.flags |= RTF_GATEWAY;
		if (tmp_entry.mask == (u32)(-1))
			tmp_entry.flags |= RTF_HOST; 

		iface_info_t *iface = if_name_to_iface(tmp_entry.if_name);
		if (iface) {
			// the desired interface
			rt_entry_t *entry = (rt_entry_t *)malloc(sizeof(rt_entry_t));
			memcpy(entry, &tmp_entry, sizeof(rt_entry_t));
			entry->iface = iface;

			list_add_tail(&entry->list, &rtable);
			n += 1;
		}
	}

	return n;
}

void load_static_rtable()
{
	char buf[ROUTE_BATCH_SIZE];
	int len = get_unparsed_route_info(buf, ROUTE_BATCH_SIZE);
	int n = parse_routing_info(buf, len);

	log(DEBUG, "Routing table of %d entries has been loaded.", n);
}

void init_rtable()
{
	init_list_head(&rtable);

	load_static_rtable();
}

void add_rt_entry(rt_entry_t *entry)
{
	list_add_tail(&entry->list, &rtable);
}

void remove_rt_entry(rt_entry_t *entry)
{
	list_delete_entry(&entry->list);
	free(entry);
}

void clear_rtable()
{
	struct list_head *head = &rtable, *tmp;
	while (head->next != head) {
		tmp = head->next;
		list_delete_entry(tmp);
		rt_entry_t *entry = list_entry(tmp, rt_entry_t, list);
		free(entry);
	}
}

void print_rtable()
{
	// Print the route records
	printf("destination\tgateway \tnetmask \tflags \tif_name \n");
	printf("-----------\t------- \t--------\t------\t------ \n");
	rt_entry_t *entry = NULL;
	list_for_each_entry(entry, &rtable, list) {
		int32_t dest = htonl(entry->dest);
		printf("%s \t0x%08x\t0x%08x \t%d \t%s\n",
				inet_ntoa(*(struct in_addr *)&dest), ntohl(entry->gw),
				entry->mask, entry->flags, entry->if_name);
	}
}
