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
#include <assert.h>
#include <string.h>
#include <stdlib.h>



#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

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
    
    /* Add initialization code here! */

} /* -- sr_init -- */



/* Custom function: handle ARP packets */
void sr_handle_arp(struct sr_instance* sr,
                   uint8_t * packet,
                   unsigned int len,
                   char* interface/* lent */)
{
  printf("Received ARP packet.\n");
  /* Check the length of the packet is a ARP request */
  int arp_len = len - sizeof(sr_ethernet_hdr_t);
  if(arp_len < sizeof(sr_arp_hdr_t)) {
    printf("ERROR: ARP packet length too small.\n");
  }
  /* Get the address of ARP header */
  sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)packet;
  sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

  /* Check if the ARP packet is valid */
  if((ntohs(arp_hdr->ar_hrd) != arp_hrd_ethernet) || (ntohs(arp_hdr->ar_pro) != ethertype_ip)) {
      printf("Error: Received ARP packet is invalid. Drop the packet.\n");
      return;
  }

  /* Check whether the packet is for the router */
  struct sr_if* dest_interface = sr_get_if_with_ip(sr, arp_hdr->ar_tip);

  /* Return if the packet not destined for this router */
  if(!dest_interface) {
      printf("Error: The received packet destination is not this router.\n");
      return;
  }

  /* Check whether the ARP packet is a request or reply */
        unsigned short arp_opcode = ntohs(arp_hdr->ar_op);
        if(arp_opcode == arp_op_request) {
            printf("Received an ARP request.\n");
            /* get the request incoming interface ethernet address */
            struct sr_if* in_interface = sr_get_interface(sr,interface);

            /* create a new Ethernet packet */
            uint8_t *new_packet = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));
            /* fill the ethernet header */
            sr_ethernet_hdr_t *new_ethernet_hdr = (sr_ethernet_hdr_t *)new_packet;
            memcpy(new_ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
            memcpy(new_ethernet_hdr->ether_shost, in_interface->addr, ETHER_ADDR_LEN);
            /*new_ethernet_hdr->ether_type = htons(ethertype_arp);*/
            new_ethernet_hdr->ether_type = ethernet_hdr->ether_type;

            /* fill the ARP header */
            sr_arp_hdr_t *new_arp_hdr = (sr_arp_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
            new_arp_hdr->ar_hrd = arp_hdr->ar_hrd;
            new_arp_hdr->ar_pro = arp_hdr->ar_pro;
            new_arp_hdr->ar_hln = arp_hdr->ar_hln;
            new_arp_hdr->ar_pln = arp_hdr->ar_pln;
            new_arp_hdr->ar_op = htons(arp_op_reply);
            memcpy(new_arp_hdr->ar_sha, in_interface->addr, ETHER_ADDR_LEN);
            memcpy(new_arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
            new_arp_hdr->ar_sip = in_interface->ip;
            new_arp_hdr->ar_tip = arp_hdr->ar_sip;

            /* print the created ARP reply packet */
            /* printf("Created a new ARP reply packet:\n");
            print_hdrs(new_packet, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));*/

            /* Send the ARP reply */
            if((sr_send_packet(sr,new_packet,sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t),in_interface->name)) != 0){
                printf("Error: sr_handle_arp: Cannot sent the ARP reply.\n");
            }
            /*checkCacheAndSendPacket(sr,new_packet,sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t),in_interface,arp_hdr->ar_sip);*/
            free(new_packet);

        }
        else if(arp_opcode==arp_op_reply)
        {
            printf("Received an ARP reply.\n");

            /*unsigned char *src_mac = arp_hdr->ar_sha;
            uint32_t src_ip = arp_hdr->ar_sip;*/
            /* Cache the ARP reply and send outstanding packets in the request queue */
            struct sr_arpreq *arp_req = sr_arpcache_insert(&sr->cache,arp_hdr->ar_sha,arp_hdr->ar_sip);
            struct sr_if* in_interface2 = sr_get_interface(sr,interface);
            if(arp_req) {
                /* get all the packets of the arp request to be sent */
                struct sr_packet *current_packet = arp_req->packets;

                while (current_packet) {

                    uint8_t *current_packet_buf = current_packet->buf;
                    /* set the current packet ethernet header */
                    sr_ethernet_hdr_t *current_eth_hdr = (sr_ethernet_hdr_t *)(current_packet_buf);
                    sr_ip_hdr_t *current_ip_hdr = (sr_ip_hdr_t *)(current_packet_buf +sizeof(sr_ethernet_hdr_t));
                    /* set the dest MAC address as the source MAC address */
                    memcpy(current_eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
                    /* set the source address as the outgoing interface of the packet */
                    memcpy(current_eth_hdr->ether_shost, in_interface2->addr, ETHER_ADDR_LEN);

                    /* Recompute the packet checksum */
                    current_ip_hdr->ip_sum=0;
                    current_ip_hdr->ip_sum=cksum(current_ip_hdr,sizeof(sr_ip_hdr_t));

                   /* printf("Current packet to send after ARP reply\n");
                    print_hdrs(current_packet->buf, current_packet->len);*/

                    /* send the packet */
                    sr_send_packet(sr, current_packet_buf, current_packet->len, in_interface2->name);

                    current_packet = current_packet->next;
                }
                /* remove the ARP request from the queue */
                sr_arpreq_destroy(&sr->cache,arp_req);
            } else {
                printf("No request found for the ARP reply.\n");
            }
        }
        /* Cannot recoganize the arp opcode */
        else {
            printf("Error: sr_handle_arp: Invalid ARP packet!\n");
        }


}

/* Custom method: find the longest prefix match of an IP address in a routing table */
struct sr_rt* longest_prefix_match(struct  sr_instance *sr, uint32_t ip) {
    struct sr_rt *longest_entry = NULL;
    struct sr_rt *current_entry = sr->routing_table;
    unsigned long maxlength = 0;
    struct in_addr addr;
    addr.s_addr = ip;

    while(current_entry) {
        if((current_entry->dest.s_addr & current_entry->mask.s_addr) == (ip & current_entry->mask.s_addr)) {
            if( !longest_entry || current_entry->mask.s_addr > longest_entry->mask.s_addr) {
                longest_entry = current_entry;
                maxlength = current_entry->mask.s_addr;
            }
        }
        current_entry = current_entry->next;
    }


    /* print the longest prefix entry */
    if(longest_entry) {
        /*printf("Find the longest prefix entry:\n");
        sr_print_routing_entry(longest_prefix_entry);*/
    } else {
        printf("Cannot find any longest prefix matching entry.\n");
    }

    return longest_entry;
}

/* Custom method: sr_handle_ip(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
 * This method handles the ip packets.
 * */
void sr_handle_ip(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface) {
    printf("Received IP packet.\n");

    /* check length of the packet */
    if(len <( sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t))) {
        printf("Error: sr_handle_ip: The packet length is too small to be an IP packet.\n");
        return;
    }

    /* verify the checksum of IP packet */
    sr_ethernet_hdr_t *ethernet_hdr= (sr_ethernet_hdr_t *)packet;
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    if(verify_checksum_ip_hdr(ip_hdr)!=1) {
        printf("Error:sr_handle_ip:The IP packet checksum is not correct.\n");
        return;
    }

    /* check whether the packet is for this router */
    uint32_t dest_ip = ip_hdr->ip_dst;

    struct sr_if * receiving_interface = sr_get_if_with_ip(sr,dest_ip);
    if(!receiving_interface){
        printf("Packet is not destined to this router. Forward the packet...\n");
        /* decrement TTL and check for timeout */
        /*ip_hdr->ip_ttl--;*/
        ip_hdr->ip_ttl = ip_hdr->ip_ttl -1;
        if(ip_hdr->ip_ttl == 0){
            printf("Time out. TTL becomes zero. Send ICMP time exceeded message.\n");
            send_icmp_type_three_msg(sr,packet,len,11, 0);
            return;
        }
        /* If not timeout, forward the packet to next hop */
        /* Look up the routing table using longest prefix match for outgoing interface */
        struct sr_rt *out_entry = longest_prefix_match(sr,ip_hdr->ip_dst);
        /*printf("OUT ENTRY\n");*/
        /*sr_print_routing_entry(out_entry);*/

        /* Send ICMP net unreachable message once not find entry using longest prefix matching */
        if(!out_entry) {
            printf("Cannot find matching entry. Send ICMP net unreachable message.\n");
            send_icmp_type_three_msg(sr,packet,len,3,0);
            return;
        }
        /* If find the entry, forward the packet */
        struct sr_if *out_interface = sr_get_interface(sr,out_entry->interface);
        if(!out_interface){
            printf("Error: Cannot find the interface to send out the packet.\n");
            return;
        }
        /* calculate the checksum for ip packet */
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
        /* Set the ethernet header destination and source and send the packet,
        which is completed by following function checkCacheAndSendPakcet */
        checkCacheAndSendPacket(sr, packet, len, out_interface, out_entry->gw.s_addr);

    } else {
        printf("Packet is for this router.\n");
        /*printf("sr_handle_ip: print the packet:\n");
        print_hdrs(packet,len);*/

        /* get the ip packet protocol*/
        if(ip_hdr->ip_p == ip_protocol_icmp) {
            printf("Received ICMP packet for this router.\n");
            /* verify the icmp checksum */
            sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
            if(verify_checksum_icmp_hdr(icmp_hdr,len)==0) {
                printf("Error:sr_handle_ip:The ICMP packet checksum is not correct.\n");
                return;
            }
            /* check the icmp message type */
            if(icmp_hdr->icmp_type == icmp_type_echo_request) {
                /* Received an ICMP echo request, send an icmp echo reply */
                send_icmp_echo_reply(sr,packet,len);
            } else {
                printf("Error: sr_handle_ip: Cannot deal with ICMP packet that is not an echo request.\n");
            }
        } else if(ip_hdr->ip_p == ip_protocol_tcp || ip_hdr->ip_p == ip_protocol_udp) {
            printf("Received TCP or UDP packet for this router. Send ICMP port unreachable message!\n");
            send_icmp_type_three_msg(sr,packet,len,3,3);

        }
     }


}


/* Custom method: send icmp reply in response to the icmp echo request */
void send_icmp_echo_reply(struct sr_instance *sr,uint8_t *packet, unsigned int len) {
    printf("Send ICMP echo reply.\n");
    /* Get the ethernet header */
    sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)packet;
    /* Get the ip header */
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    /* Get the icmp header */
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    /* get the longest prefix matching entry for source IP */
    struct sr_rt *matching_entry = longest_prefix_match(sr,ip_hdr->ip_src);
    if(!matching_entry){
        printf("Error:send_icmp_echo_reply: Cannot find the matching entry in routing table.\n");
        return;
    }

    /* Get outgoing interface from the matching entry */
    struct sr_if *out_interface = sr_get_interface(sr, matching_entry->interface);

    /* Set the ethernet header destination and source mac address */
    /* The ethernet header is set by checkCacheAndSendPacket */
    memcpy(ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(ethernet_hdr->ether_shost, out_interface->addr, ETHER_ADDR_LEN);
    /* Set the icmp header */
    icmp_hdr->icmp_type = 0;
    icmp_hdr->icmp_code = 0;
    /* Compute the checksum of the icpm packet */
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr,len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));
    /* Set the ip header */
    uint32_t new_ip_src = ip_hdr->ip_dst;
    ip_hdr->ip_dst = ip_hdr->ip_src;
    ip_hdr->ip_src = new_ip_src;
    /* compute the ip checksum */
    ip_hdr->ip_sum =0;
    ip_hdr->ip_sum = cksum(ip_hdr,sizeof(sr_ip_hdr_t));

    /* Send the packet back to source */
    checkCacheAndSendPacket(sr,packet,len,out_interface,matching_entry->gw.s_addr);

}


/* Custom method: void send_icmp_type_three_msg(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface, uint8_t icmp_type,uint8_t icmp_code);
 *
 * Send ICMP message according to given type and code.
*/

void send_icmp_type_three_msg(struct sr_instance *sr, uint8_t *packet, unsigned int len, uint8_t icmp_type,uint8_t icmp_code) {
    printf("Send the ICMP message.  \n");
    /* Get the ethernet header */
    sr_ethernet_hdr_t *ethernet_hdr = (sr_ethernet_hdr_t *)packet;
    /* Get the ip header */
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    /* get the longest prefix matching entry for source IP */
    struct sr_rt *matching_entry = longest_prefix_match(sr,ip_hdr->ip_src);
    if(!matching_entry){
        printf("Error: send_icmp_type_three_msg: Cannot find the matching entry in routing table.\n");
        return;
    }
    /* Get outgoing interface from the matching entry */
    struct sr_if *out_interface = sr_get_interface(sr, matching_entry->interface);

    /* Construct a new packet */
    unsigned int new_packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    uint8_t *new_packet = malloc(new_packet_len);

    /* Get new packet ethernet header */
    sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t * )new_packet;
    /* Get the new packet ip header */
    sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
    /* get the new packet icmp header */
    sr_icmp_t3_hdr_t *new_icmp_hdr = (sr_icmp_t3_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    /* set the new ethernet header */
    memcpy(new_eth_hdr->ether_dhost, ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(new_eth_hdr->ether_shost, out_interface->addr, ETHER_ADDR_LEN);
    new_eth_hdr->ether_type = htons(ethertype_ip);


    /* Set the new ip header */
    /*new_ip_hdr->ip_hl = 5;*/
    new_ip_hdr->ip_v = 4;
    new_ip_hdr->ip_hl = ip_hdr->ip_hl;
    new_ip_hdr->ip_tos = 0;
    new_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    new_ip_hdr->ip_id = htons(0);
    new_ip_hdr->ip_off = htons(IP_DF);
    new_ip_hdr->ip_ttl = 64;
    new_ip_hdr->ip_p = ip_protocol_icmp;


    new_ip_hdr->ip_src = out_interface->ip;
    new_ip_hdr->ip_dst = ip_hdr->ip_src;
    new_ip_hdr->ip_sum = 0;
    new_ip_hdr->ip_sum = cksum(new_ip_hdr,sizeof(sr_ip_hdr_t));

    /* Set the icmp type 3 header */
    new_icmp_hdr->icmp_type = icmp_type;
    new_icmp_hdr->icmp_code = icmp_code;
    new_icmp_hdr->icmp_sum = 0;
    new_icmp_hdr->unused = 0;
    new_icmp_hdr->next_mtu = 0;
    memcpy(new_icmp_hdr->data,ip_hdr,ICMP_DATA_SIZE);
    new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr,sizeof(sr_icmp_t3_hdr_t));

    /*printf("The icmp packet send out:\n");
    print_hdrs(new_packet,new_packet_len);*/

    /* Send the packet */
    checkCacheAndSendPacket(sr,new_packet,new_packet_len,out_interface, matching_entry->gw.s_addr);
    free(new_packet);

}

/* Custom method: int verify_checksum_ip_hdr(sr_ip_hdr_t *ip_hdr);
   Verify the checksum of an IP header
   Returns 1 if correct, otherwise returns 0.
 */
int verify_checksum_ip_hdr(sr_ip_hdr_t *ip_hdr) {
    uint16_t actual_checksum = ip_hdr->ip_sum;
    /* set the checksum to zero and recompute it*/
    ip_hdr->ip_sum  = 0;
    uint16_t computed_checksum = cksum(ip_hdr,sizeof(sr_ip_hdr_t));
    ip_hdr->ip_sum = actual_checksum;
    /* compare the actual checksum with computed checksum */
    printf("Actual checksum: %d Computed checksum: %d\n", actual_checksum, computed_checksum);
    if(actual_checksum != computed_checksum) {
        printf("Error: verify_checksum_ip_hdr: checksum is not correct.\n");
        return 0;
    }
    return 1;
}

/* Custom method: int verify_checksum_icmp_hdr(sr_icmp_hdr_t, *icmp_hdr)
 * This method verifies whether the checksum of an ICMP header is correct.
 * Returns 1 if correct, otherwise returns 0.
 */
int verify_checksum_icmp_hdr(sr_icmp_hdr_t *icmp_hdr, unsigned int len) {
    uint16_t actual_checksum = icmp_hdr->icmp_sum;
    icmp_hdr->icmp_sum = 0;
    int icmp_len = len - sizeof(sr_ethernet_hdr_t) -sizeof(sr_ip_hdr_t);
    uint16_t computed_checksum = cksum(icmp_hdr, icmp_len);
    icmp_hdr->icmp_sum = actual_checksum;

    /* compare the actual checksum with computed checksum */
    printf("Actual checksum: %d Computed checksum: %d\n", actual_checksum, computed_checksum);
    if(actual_checksum != computed_checksum) {
        printf("Error: verify_checksum_icmp_hdr: checksum is not correct.\n");
        return 0;
    }
    return 1;

}

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
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/
void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */
  /* print the received packet */
  /*print_hdrs(packet, len);*/

  /* Ethernet packet sanity check */
  int minlength = sizeof(sr_ethernet_hdr_t);

  if(len < minlength) {
      printf("Error: Packet too small, drop it!\n");
      return;
  }

  uint16_t ethtype = ethertype(packet);
  if(ethtype == ethertype_arp) {
      sr_handle_arp(sr, packet, len, interface);
  } else if (ethtype == ethertype_ip){
      sr_handle_ip(sr,packet,len,interface);
  } else {
      printf("Cannot handle the Ethernet Type.\n");
  }




}/* end sr_ForwardPacket */

