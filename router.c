#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <string.h>

#include "queue.h"
#include "lib.h"
#include "protocols.h"

#define IP_HDR 0x0800
#define ARP_HDR 0x0806
#define ICMP_ERROR_IP_HEADER_SIZE 2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 8

uint8_t broadcast_mac[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
uint8_t target_mac[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

// Trie node structure
typedef struct trie_node {
	struct trie_node *left_child;
	struct trie_node *right_child;
	struct route_table_entry *best_route;
} trie_node;

void build_trie(trie_node *root, struct route_table_entry *rtable, size_t rtable_len) {
	printf("Building routing table trie... Please wait\n");
	// Iterate through the routing table
	for (int i = 0; i < rtable_len; i++) {
		trie_node *current_node = root;

		// Get the prefix of the current route
		uint32_t prefix = ntohl(rtable[i].prefix);

		// Go through each bit of the current ip and advance in the trie
		// Stop when the furthest bit available has been reached
		for (int j = 0; j < 32 && ((rtable[i].mask >> j) & 1); j++) {
			uint8_t bit = (prefix >> (31 - j)) & 1;

			if (!bit) {
				if (!current_node->left_child) {
					current_node->left_child = (trie_node *)calloc(1, sizeof(trie_node));
					DIE(!current_node->left_child, "Failed trie node memory allocation");
				}
				current_node = current_node->left_child;
			} else {
				if (!current_node->right_child) {
					current_node->right_child = (trie_node *)calloc(1, sizeof(trie_node));
					DIE(!current_node->right_child, "Failed trie node memory allocation");
				}
				current_node = current_node->right_child;
			}
		}

		// Associate the current route with the current node
		current_node->best_route = &rtable[i];
	}
}

struct route_table_entry *trie_lookup(trie_node *root, uint32_t ip) {
	trie_node *current_node = root;
	ip = ntohl(ip);

	// Begin looking from the root, iterate through each bit
	// Stop when the furthest bit available has been reached
	for (int bit = 0; bit < 32; bit++) {
		uint8_t current_bit = (ip >> (31 - bit)) & 1;

		if (!current_bit) {
			if (!current_node->left_child)
				return current_node->best_route;
			current_node = current_node->left_child;
		} else {
			if (!current_node->right_child)
				return current_node->best_route;
			current_node = current_node->right_child;
		}
	}

	return NULL;
}

int router_is_destination(uint32_t ip) {
	for (int interface = 0; interface < ROUTER_NUM_INTERFACES; interface++) {
		char *interface_ip = get_interface_ip(interface);

		struct in_addr *ip_structure = (struct in_addr *)calloc(1, sizeof(struct in_addr));
		DIE(!ip_structure, "in_addr memory allocation fail");

		int rc = inet_aton((const char *)interface_ip, ip_structure);
		DIE(!rc, "inet_aton returned zero; invalid ip");

		if (ip_structure->s_addr == ip) {
			return 1;
		}
	}

	return 0;
}

struct arp_table_entry *get_mac_entry(uint32_t ip, struct arp_table_entry *arp_table, size_t arp_table_len) {
	for (int i = 0; i < arp_table_len; i++)
		if (arp_table[i].ip == ip)
			return &arp_table[i];

	return NULL;
}

void add_arp_entry(struct arp_table_entry *arp_table, size_t *arp_table_len, uint32_t ip, uint8_t *mac) {
	arp_table[*arp_table_len].ip = ip;
	memcpy(arp_table[*arp_table_len].mac, mac, 6);

	(*arp_table_len)++;
}

void send_arp_request(uint32_t interface, uint32_t requested_ip, uint8_t *sender_hdr_addr, uint32_t sender_ip) {
	// Allocated memory for the ethernet frame
	void *ethernet_frame = (void *)calloc(1, sizeof(struct ether_header) + sizeof(struct arp_header));
	DIE(!ethernet_frame, "Failed ethernet header memory allocation");

	// Get the pointer to the ethernet header
	struct ether_header *ethernet_request = (struct ether_header *)ethernet_frame;

	// Fill out the ethernet structure
	memcpy(ethernet_request->ether_dhost, broadcast_mac, 6);
	memcpy(ethernet_request->ether_shost, sender_hdr_addr, 6);

	ethernet_request->ether_type = htons(ARP_HDR);

	// Get the pointer to the arp header
	struct arp_header *arp_request = (struct arp_header *)(ethernet_frame + sizeof(struct ether_header));

	// Fill out the arp structure
	arp_request->htype = htons(1);
	arp_request->ptype = htons(IP_HDR);
	
	arp_request->hlen = 6;
	arp_request->plen = 4;

	// Set operation type to 1(request)
	arp_request->op = htons(1);

	memcpy(arp_request->sha, sender_hdr_addr, 6);
	arp_request->spa = sender_ip;

	memcpy(arp_request->tha, target_mac, 6);
	arp_request->tpa = requested_ip;

	// Send the request
	size_t len = sizeof(struct ether_header) + sizeof(struct arp_header);
	size_t sent_len = 0;

	while (len > 0) {
		int rc = send_to_link(interface, ethernet_frame, len);
		sent_len += rc;
		len -= sent_len;
	}
}

void send_icmp_message(int type, void *packet, int interface, size_t packet_length) {
	// if the type is echo request, we need to send an echo reply
	// exclusive for the router
	if (type == 8) {
		// change the request type to 0 (echo reply)
		struct ether_header *eth_hdr = (struct ether_header *)packet;
		struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));
		struct icmphdr *icmp_hdr = (struct icmphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
		icmp_hdr->type = 0;

		icmp_hdr->checksum = 0;
		// Recalculate icmp_hdr checksum
		icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)));

		// swap mac addresses
		uint8_t mac_swap[6];
		memcpy(mac_swap, eth_hdr->ether_dhost, 6);
		memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
		memcpy(eth_hdr->ether_shost, mac_swap, 6);


		// Swap the source and destination ip addresses
		uint32_t ip_swap = ip_hdr->saddr;
		ip_hdr->saddr = ip_hdr->daddr;
		ip_hdr->daddr = ip_swap;

		ip_hdr->check = 0;
		// Recalculate ip_hdr checksum
		ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

		size_t len = packet_length;
		size_t sent_len = 0;

		while (len) {
			int rc = send_to_link(interface, packet, len);
			sent_len += rc;
			len -= sent_len;
		}

		return;
	}
	// Allocate memory as follows:
	// NEW_ETH_FRAME + NEW_IP_HEADER->(NEW_ICMP_HEADER->(OLD_IP_HEADER + FIRST_8_BYTES_OF_OLD_ICMP_HEADER))
	void *icmp_packet = (void *)calloc(1, sizeof(struct ether_header) + 2 * sizeof(struct iphdr) + 2 * sizeof(struct icmphdr));
	DIE(!icmp_packet, "Failed icmp packet memory allocation");

	struct ether_header *new_eth_hdr = (struct ether_header *)icmp_packet;
	struct iphdr *new_ip_hdr = (struct iphdr *)(icmp_packet + sizeof(struct ether_header));
	struct icmphdr *new_icmp_hdr = (struct icmphdr *)(icmp_packet + sizeof(struct ether_header) + sizeof(struct iphdr));

	struct iphdr *old_ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));

	// Write the new eth header
	new_eth_hdr->ether_type = htons(IP_HDR);
	memcpy(new_eth_hdr->ether_shost, ((struct ether_header *)packet)->ether_dhost, 6);
	memcpy(new_eth_hdr->ether_dhost, ((struct ether_header *)packet)->ether_shost, 6);

	// Write the new ip header
	new_ip_hdr->ihl = 5;
	new_ip_hdr->version =4;

	new_ip_hdr->tos = 0;

	new_ip_hdr->tot_len = htons(ICMP_ERROR_IP_HEADER_SIZE);
	new_ip_hdr->id = htons(1);
	new_ip_hdr->frag_off = 0;

	new_ip_hdr->ttl = 64;
	new_ip_hdr->check = 0;

	new_ip_hdr->protocol = 1;

	// presupun ca get_interface_ip intoarce in host order
	char *interface_ip = get_interface_ip(interface);
	struct in_addr *ip_structure = (struct in_addr *)calloc(1, sizeof(struct in_addr));
	DIE(!ip_structure, "in_addr memory allocation fail");

	int rc = inet_aton((const char *)interface_ip, ip_structure);
	DIE(!rc, "inet_aton returned zero; invalid ip");

	new_ip_hdr->saddr = ip_structure->s_addr;
	new_ip_hdr->daddr = old_ip_hdr->saddr;

	// Write the new icmp hdr
	new_icmp_hdr->type = type;
	new_icmp_hdr->code = 0;
	new_icmp_hdr->checksum = 0;
	// 4 bytes are unused

	// Now we need to stitch the old ip header and the first 8 bytes from the old icmp header
	memcpy(((void *)new_icmp_hdr) + sizeof(struct icmphdr), old_ip_hdr, sizeof(struct iphdr) + 8);

	// Compute the checksum for new icmp header
	new_icmp_hdr->checksum = htons(checksum((uint16_t *)new_icmp_hdr, sizeof(struct icmphdr) + sizeof(struct iphdr) + 8));

	// Compute the checksum for the new ip header
	new_ip_hdr->check = htons(checksum((uint16_t *)new_ip_hdr, 2 * sizeof(struct iphdr) + sizeof(struct icmphdr) + 8));

	size_t len = ICMP_ERROR_IP_HEADER_SIZE + sizeof(struct ether_header);
	size_t sent_len = 0;

	while (len) {
		int rc = send_to_link(interface, icmp_packet, len);
		sent_len += rc;
		len -= sent_len;
	}
}

void solve_queue(queue arp_awaiting_queue, struct arp_table_entry *arp_table, size_t arp_table_len, trie_node *root) {
	queue still_unfound_queue = queue_create();

	// Iterate through the current queue, send the now sendable packets
	// Add the unresolved packets to the still_unfound_queue and at the end at these to the original queue
	while (!queue_empty(arp_awaiting_queue)) {
		void *packet = queue_deq(arp_awaiting_queue);

		// Get the pointer to the ethernet header;
		struct ether_header *eth_hdr = (struct ether_header *)packet;

		// Get the pointer to the ip header
		struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ether_header));

		// Try to find the destination mac
		struct arp_table_entry *destination_mac_entry = get_mac_entry(ip_header->daddr, arp_table, arp_table_len);

		if (!destination_mac_entry) {
			// The address is yet to be cached, keep waiting
			printf("Address %d still not cached; Skipping\n", ip_header->daddr);
			queue_enq(still_unfound_queue, packet);
			continue;
		}

		// Rewrite the destination mac
		memcpy(eth_hdr->ether_dhost, destination_mac_entry->mac, 6);

		struct route_table_entry *best_route = trie_lookup(root, ip_header->daddr);
		if (!best_route) {
			printf("Destination unreachable; Dropping\n");
			send_icmp_message(11, packet, best_route->interface, MAX_PACKET_LEN);
			continue;
		}

		// Send the packet on its way to the next hop
		size_t len = sizeof(struct ether_header) + ntohs(ip_header->tot_len);
		size_t sent_len = 0;
		while (len) {
			int rc = send_to_link(best_route->interface, packet + sent_len, len);
			sent_len += rc;
			len -= sent_len;
		}
		uint8_t *ip_dest = (uint8_t *)&ip_header->daddr;
		uint8_t *ip_src = (uint8_t *)&ip_header->saddr;
		printf("Finished sending initial packet from IP Address %hu.%hu.%hu.%hu to IP Address %hu. %hu. %hu. %hu on interface %d\n", ip_src[0], ip_src[1], ip_src[2], ip_src[3], ip_dest[0], ip_dest[1], ip_dest[2], ip_dest[3], best_route->interface);
	}

	// Add each remaining packet from the still_unfound_queue to the origin queue
	while (!queue_empty(still_unfound_queue))
		queue_enq(arp_awaiting_queue, queue_deq(still_unfound_queue));

	free(still_unfound_queue);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argc - 2, argv + 2);

	// Initialize routing table
	struct route_table_entry *rtable = (struct route_table_entry *)calloc(100000, sizeof(struct route_table_entry));
	DIE(!rtable, "Failed routing table memory allocation");

	// Populate routing table
	size_t rtable_len = read_rtable(argv[1], rtable);

	// Get the trie root
	trie_node *root = (trie_node *)calloc(1, sizeof(trie_node));
	DIE(!root, "Failed trie root memory allocation");

	// Build the trie
	build_trie(root, rtable, rtable_len);

	// Initialize arp table
	struct arp_table_entry *arp_table = (struct arp_table_entry *)calloc(100000, sizeof(struct arp_table_entry));
	DIE(!arp_table, "Failed arp table memory allocation");

	// Initial length; might be updated after caching new entries
	// As a convention, the arp table will keep the ips in network order to skip using ntohl and htonl respectively
	size_t arp_table_len = 0;

	// Create the arp queue
	queue arp_awaiting_queue = queue_create();

	printf("Begin waiting...\n");
	while (1) {

		int interface;
		size_t len;

		printf("Resume waiting...\n");
		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		printf("Received a packet...\n");

		struct ether_header *eth_hdr = (struct ether_header *) buf;
		/* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */

		// Check the received packet type
		if (ntohs(eth_hdr->ether_type) == IP_HDR) {
			printf("Packet is of ether type 0x0800(IP)\n");
			// Get ip header
			struct iphdr *ip_header = (struct iphdr *)(buf + sizeof(struct ether_header));

			// Check if the packet is for the router
			// ip_header->daddr must be in network order as inet_aton returns in network order
			if (router_is_destination(ip_header->daddr)) {
				printf("The router was the destination...\n");
				
				struct icmphdr *icmp_header = (struct icmphdr *)(buf + sizeof(struct ether_header) + sizeof(struct iphdr));

				// Verify the checksum of the icmp header
				uint16_t icmp_checksum = ntohs(icmp_header->checksum);
				icmp_header->checksum = 0;
				uint16_t computed_icmp_checksum = checksum((uint16_t *)icmp_header, sizeof(struct icmphdr));

				if (icmp_checksum != computed_icmp_checksum) {
					printf("Corrupted ICMP packet; Dropping\n");
					continue;
				}

				if (icmp_header->type == 8) { // echo request
					printf("Echo request\n");
					send_icmp_message(8, buf, interface, len);
				} else {
					printf("Unrecognized request type; Dropping\n");
				}
				continue;
			}

			// Check the checksum
			uint16_t check = ntohs(ip_header->check);
			printf("Received checksum : %hu(host order) and %hu(network order)\n", check, ip_header->check);
			ip_header->check = 0;
			uint16_t computed_checksum = checksum((uint16_t *)ip_header, sizeof(struct iphdr));
			printf("Computed checksum : %hu(host order) and %hu(network order)\n", computed_checksum, htons(computed_checksum));

			if (computed_checksum != check) {
				printf("Corrupted packet; Dropping\n");
				continue;
			}
			printf("Checksum ok...\n");

			// Check and update the TTL
			if (ip_header->ttl <= 1) {
				printf("Time exceeded; Dropping\n");
				send_icmp_message(11, buf, interface, len);
				continue;
			} else {
				ip_header->ttl--;
			}
			printf("TTL ok... New ttl : %d\n", ip_header->ttl);

			// Update checksum field
			ip_header->check = htons(checksum((uint16_t *)ip_header, sizeof(struct iphdr)));
			printf("New checksum : %hu\n", ip_header->check);

			// Look up the destination address in the routing table
			struct route_table_entry *best_route = trie_lookup(root, ip_header->daddr);
			if (!best_route) {
				printf("Destination unreachable; Dropping\n");
				send_icmp_message(3, buf, interface, len);
				continue;
			}

			// Rewrite header

			// Rewrite sender mac
			get_interface_mac(best_route->interface, eth_hdr->ether_shost);

			// Try to find the destination mac
			struct arp_table_entry *destination_mac_entry = get_mac_entry(best_route->next_hop, arp_table, arp_table_len);

			// If the looked up address is not yet cached, we have to send an arp request
			// Besides, store the current request in queue
			if (!destination_mac_entry) {
				printf("Didn't find mac address...\n");
				// Store the current request in queue
				// Allocate memory for new packet
				void *packet_copy = (void *)calloc(len, sizeof(char));
				DIE(!packet_copy, "Failed packet copy memory allocation");
				
				// Copy the packet information
				memcpy(packet_copy, buf, len);

				// Enqueue the request
				queue_enq(arp_awaiting_queue, packet_copy);

				// Send ARP request
				// Sender hardware address must be the mac address of the interface
				// on which the next op is to be sent
				uint8_t *sender_hdr_addr = (uint8_t *)calloc(6, sizeof(uint8_t));
				DIE(!sender_hdr_addr, "Failed sender header address memory allocation");
				get_interface_mac(best_route->interface, sender_hdr_addr);

				char *interface_ip = get_interface_ip(best_route->interface);

				struct in_addr *ip_structure = (struct in_addr *)calloc(1, sizeof(struct in_addr));
				DIE(!ip_structure, "in_addr memory allocation fail");

				int rc = inet_aton((const char *)interface_ip, ip_structure);
				DIE(!rc, "inet_aton returned zero; invalid ip");

				send_arp_request(best_route->interface, ip_header->daddr, sender_hdr_addr, ip_structure->s_addr);

				printf("Sent request for :\n");
				uint8_t *ip_dest = (uint8_t *)&ip_header->daddr;
				uint8_t *ip_src = (uint8_t *)&ip_header->saddr;
				printf("packet from IP Address %hu.%hu.%hu.%hu to IP Address %hu. %hu. %hu. %hu on interface %d\n", ip_src[0], ip_src[1], ip_src[2], ip_src[3], ip_dest[0], ip_dest[1], ip_dest[2], ip_dest[3], best_route->interface);

				// Skip the rest of the work for now
				continue;
			}

			// Rewrite the destination mac
			memcpy(eth_hdr->ether_dhost, destination_mac_entry->mac, 6);

			printf("Successfully parsed; Sending packet...\n");

			// Send the packet on its way to the next hop
			// Do so in a while, in case write fails to send all in one try
			size_t sent_len = 0;
			while (len) {
				int rc = send_to_link(best_route->interface, buf + sent_len, len);
				sent_len += rc;
				len -= sent_len;
			}
		} else if (ntohs(eth_hdr->ether_type) == ARP_HDR) {
			printf("Packet is of ether type 0x0806(ARP)\n");
			// Get the pointer to the arp header
			struct arp_header *arp_header = (struct arp_header *)(buf + sizeof(struct ether_header));

			// If the request is an arp reply
			if (ntohs(arp_header->op) == 2) {
				printf("Got an ARP reply, updating ARP table and solving queue...\n");
				// Add the new entry to the arp table
				add_arp_entry(arp_table, &arp_table_len, arp_header->spa, arp_header->sha);
				printf("Updated arp table\nSolving queue\n");
				printf("The new entry's mac is : %d %02x:%02x:%02x:%02x:%02x:%02x\n", arp_header->spa, arp_header->sha[0], arp_header->sha[1], arp_header->sha[2], arp_header->sha[3], arp_header->sha[4], arp_header->sha[5]);
				uint8_t *ip = (uint8_t *)&arp_header->spa;
				printf("The new entry's IP is : %d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);

				// Resolve associated requests that are in the queue
				solve_queue(arp_awaiting_queue, arp_table, arp_table_len, root);
				printf("Solved available queue\n");
			} else if (ntohs(arp_header->op) == 1) { // if the request is an arp request
				// We need to get the mac address of the target ip address and return it
				// in an arp reply

				printf("Got an ARP request; Sending it...\n");

				// Change the operation type to 2 (reply)
				arp_header->op = htons(2);

				uint8_t temp_swap_tha[6];
				uint32_t temp_swap_tpa = arp_header->tpa;

				memcpy(temp_swap_tha, arp_header->tha, 6);

				// The target mac becomes the sender mac and the same for the ips
				memcpy(arp_header->tha, arp_header->sha, 6);
				arp_header->tpa = arp_header->spa;

				arp_header->spa = temp_swap_tpa;
				get_interface_mac(interface, arp_header->sha);

				// update ethernet header
				memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
				memcpy(eth_hdr->ether_shost, arp_header->sha, 6);

				printf("Sending reply...\n");
				send_to_link(interface, buf, sizeof(struct ether_header) + sizeof(struct arp_header));
			}
		} else {
			printf("Unrecognized packet received\nDropping\n");
		}
	}

	free(rtable);
	free(arp_table);
	free(arp_awaiting_queue);
}
