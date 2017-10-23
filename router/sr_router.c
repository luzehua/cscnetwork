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

void sr_init(struct sr_instance *sr)
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

void sr_handlepacket(struct sr_instance *sr,
                     uint8_t *packet /* lent */,
                     unsigned int len,
                     char *interface /* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n", len);

    printf("Interface: %s\n", interface);
    sr_print_routing_table(sr);
    print_hdr_eth(packet);

    sr_ethernet_hdr_t *etherhdr = (sr_ethernet_hdr_t *)packet;

    print_addr_eth("*** -> Received packet's desnitation: " etherhdr->ether_dhost);
    print_addr_eth("*** -> Received packet's desnitation: " etherhdr->ether_shost);

    /*
  uint16_t ethertype(uint8_t *buf) {
    sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
    return ntohs(ehdr->ether_type);
  }
  */
    uint16_t *payload = (packet + sizeof(sr_ethernet_hdr_t));

    switch (ethertype(packet))
    {

    case ethertype_arp:
        printf("*** An ARP packet\n");
        sr_arp_hdr_t *arphdr = (sr_arp_hdr_t *)payload;
        if (arphdr->ar_hrd != arp_hrd_ethernet)
        {
            return;
        }

        /* Check if router's interface is destination*/
        struct sr_if *dest = sr_get_interface_by_ipaddr(sr, iphdr->ip_dst);

        switch (arphdr->ar_op)
        {
        case arp_op_request:
            /* Reply back if its a ARP request*/
            break;

        case arp_op_reply:
            /* TODO: cache it if a ARP response*/
            break;
        }
        break;

    case ethertype_ip:
        /* IP packet */
        sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)payload;

        /* Check length and checksum */
        if (verifyip(iphdr) == -1)
        {
            return;
        }

        struct sr_if *dest = sr_get_interface_by_ipaddr(sr, iphdr->ip_dst);

        if (dest)
        {
            switch (iphdr->ip_p)
            {
            /* ICMP messages */
            case ip_protocol_icmp:
                /*
            Echo reply (type 0)Sent in response to an echo request (ping) to one of the router’s interfaces. 
            */

                break;

            /* TCP messages: drop packet and send type 3 ICMP--destination unreachable*/
            case ip_protocol_tcp:
                break;
            /* UDP messages: drop packet and send type 3 ICMP--destination unreachable*/
            case ip_protocol_udp;
                break;
            }
        } else 
        {
            /* Not the destination, forward packet*/
            iphdr->ip_ttl--;

            /* Discard packet is time exceeded and sent out ICMP message */
            if (iphdr->ip_ttl == 0) {
                /* TODO: send ICMP message */
                return;
            }

            /* recompute the checksum over the changed header before forwarding it to the next hop. 
            iphdr->ip_sum = 0;
            iphdr->ip_sum = cksum(iphdr, sizeof(sr_ip_hdr_t));
            */
            
            /*  TODO: find the longest prefix match of a destination IP address in the routing table  */
                




            
            
        }
        break;
    }

} /* end sr_ForwardPacket */




int sanity_check_packet(sr_ip_hdr_t *headers)
{
    /* meets minimum length */
    if (headers->ip_len < 20 && headers->ip_len > 60) 
    {
        return -1;
    }
    /* Verify checksum */
    if (cksum(headers, sizeof(sr_ip_hdr_t)) != headers->ip_sum)
    {
        return -1;
    }
    return 0;
}

void send_packet(struct sr_instance *sr,
                uint8_t *packet /* lent */,
                unsigned int len,
                struct sr_if *interface,
                uint32_t destip)
{
  /*   
  # When sending packet to next_hop_ip
   entry = arpcache_lookup(next_hop_ip)

   if entry:
       use next_hop_ip->mac mapping in entry to send the packet
       free entry
   else:
       req = arpcache_queuereq(next_hop_ip, packet, len)
       handle_arpreq(req)
  */
  struct sr_arpentry *cached = sr_arpcache_lookup(sr->cache, arphdr->ar_tip);

  if (cached) {
      /* send out packet */
      sr_ethernet_hdr_t *etherhdr = (sr_ethernet_hdr_t *)packet;
      /*Get destination addr from cached table*/
      memcpy(ehdr->ether_dhost, cached->mac, ETHER_ADDR_LEN);
      /* Get source addr MAC address from the interface that sent it */
      memcpy(ehdr->ether_shost, interface->addr, ETHER_ADDR_LEN);
      sr_send_packet(sr, packet, len, interface->name);
      
      free(cached);
  } else {
      /*Queue ARP request*/
      struct sr_arpreq *req = sr_arpcache_queuereq(sr->cache, destip, packet, len, interface);
      handle_arpreq(sr, req);
  }
}
