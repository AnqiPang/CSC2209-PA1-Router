#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"

/* Custom Method: check the number of times that arp request has been sent,
 * and decide whether to send an icmp msg or arp request.
 * void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *arpreq);
 * if difftime(now, req->sent) > 1.0
           if req->times_sent >= 5:
               send icmp host unreachable to source addr of all pkts waiting
                 on this request
               arpreq_destroy(req)
           else:
               send arp request
               req->sent = now
               req->times_sent++
 *
 * */
void handle_arpreq(struct sr_instance *sr, struct sr_arpreq *arpreq) {
    /* get current time*/
    time_t current_time;
    time(&current_time);
   /* time_t now = time(NULL);
    pthread_mutex_lock(&sr->cache.lock);*/
    /* check the difference time between current time and request sent time */
    if(difftime(current_time, arpreq->sent) > 1.0) {
        if(arpreq->times_sent >= 5){
            /* get all the packets waiting for this arp request */
            struct sr_packet *waiting_packet = arpreq->packets;
            /*  send icmp host unreachable to source addr of all pkts waiting */
            while (waiting_packet){
                printf("send icmp msg: host unrechable");
                send_icmp_type_three_msg(sr,waiting_packet->buf,waiting_packet->len,3,(uint8_t)1);
                waiting_packet = waiting_packet->next;
/*
                send_icmp_type_three_msg(sr,waiting_packet->buf,waiting_packet->len,)
*/
            }
            sr_arpreq_destroy(&sr->cache,arpreq);
        } else {
            printf("Send ARP request.\n");
            /* constrcut an ARP request packet */
            uint8_t *new_arp_packet = malloc(sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t));

            /* create the ethernet header */
            sr_ethernet_hdr_t *new_arp_ethernet_hdr = (sr_ethernet_hdr_t *)new_arp_packet;
            /* source interface is the outgoing interface of the arp request packet */
            struct sr_if *src_interface = sr_get_interface(sr,arpreq->packets->iface);
            if(!src_interface) {
                printf("Error:handle_arpreq: Cannot get outgoing interface.\n");
                return;
            }

            memcpy(new_arp_ethernet_hdr->ether_shost, src_interface->addr, ETHER_ADDR_LEN);
            /* destination MAC address is FF:FF:FF:FF */
            memset(new_arp_ethernet_hdr->ether_dhost, 0xFF,ETHER_ADDR_LEN);
            new_arp_ethernet_hdr->ether_type = htons(ethertype_arp);

            /* create the ARP header */
            sr_arp_hdr_t *new_arp_hdr = (sr_arp_hdr_t *)(new_arp_packet + sizeof(sr_ethernet_hdr_t));
            new_arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
            new_arp_hdr->ar_pro = htons(ethertype_ip);
            new_arp_hdr->ar_hln = (unsigned char )ETHER_ADDR_LEN;
            new_arp_hdr->ar_pln = (unsigned char)sizeof(uint32_t);
            /*new_arp_hdr->ar_hln = 6;
            new_arp_hdr->ar_pln = 4;*/
            new_arp_hdr->ar_op = (unsigned short)htons(arp_op_request);
            memcpy(new_arp_hdr->ar_sha, src_interface->addr, ETHER_ADDR_LEN);
            /* the target mac address is 00:00:00:00 */
            memset(new_arp_hdr->ar_tha, 0x00, ETHER_ADDR_LEN);
            new_arp_hdr->ar_sip = src_interface->ip;
            new_arp_hdr->ar_tip = arpreq->ip;

            printf("handle_arpreq: Created the ARP request packet\n");
            print_hdrs(new_arp_packet,sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t));

            /* send the arp request packet */
            unsigned int arp_len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t);
            if(sr_send_packet(sr, new_arp_packet,arp_len, src_interface->name) !=0 ){
                printf("Error: handle_arpreq: Cannot send the ARP request!\n");
            } else{
                printf("Success: Send the ARP request successfully!\n");
            }
            free(new_arp_packet);

            /* update the arp request */
            arpreq->sent = time(NULL);
            arpreq->times_sent ++;
            arpreq->sent = current_time;


        }
    }
/*
    pthread_mutex_unlock(&sr->cache.lock);
*/
}

/* Custom method: check arp cache and the packet
 *  When sending packet to next_hop_ip
   entry = arpcache_lookup(next_hop_ip)

   if entry:
       use next_hop_ip->mac mapping in entry to send the packet
       free entry
   else:
       req = arpcache_queuereq(next_hop_ip, packet, len)
       handle_arpreq(req)

 * */
void checkCacheAndSendPacket(struct sr_instance* sr /* borrowed */,
                             uint8_t* packet /* borrowed */ ,
                             unsigned int len,
                             struct sr_if *interface,
                             uint32_t ip)
{
    printf("Check cache and send packet.\n");
    /* Look up the arp cache to find the entry with matched ip */
    struct sr_arpentry *entry = sr_arpcache_lookup(&sr->cache, ip);
    if(entry){
        printf("Find the entry in arp cahche.\n");
        sr_ethernet_hdr_t *ethernet_hdr_addr = (sr_ethernet_hdr_t *)packet;
        memcpy(ethernet_hdr_addr->ether_dhost, entry->mac, ETHER_ADDR_LEN );

        /* get the source interface hardware address of the packet */
        /*struct sr_if *src_interface = sr_get_interface(sr, iface);*/
       /* memcpy(ethernet_hdr_addr->ether_shost, src_interface->addr, ETHER_ADDR_LEN );*/
        memcpy(ethernet_hdr_addr->ether_shost, interface->addr, ETHER_ADDR_LEN );
        /*sr_send_packet(sr,packet,len,iface);*/
        sr_send_packet(sr,packet,len,interface->name);
        free(entry);
    } else {
        printf("Not found Entry. Add the arp request to the queue.\n");
        printf("The cached packet.\n");
        print_hdrs(packet,len);
        /*struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache),ip,packet,len,iface);*/
        struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache,ip,packet,len,interface->name);
        handle_arpreq(sr,req);
    }
}

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    /* Fill this in */
    struct sr_arpreq *request = sr->cache.requests;
    while (request) {
        struct sr_arpreq *next = request->next;
        handle_arpreq(sr,request);
        request = next;
    }
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

