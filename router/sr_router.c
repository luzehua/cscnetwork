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

  sr_ethernet_hdr_t *etherhdr = (sr_ethernet_hdr_t *) packet;

  print_addr_eth("*** -> Received packet's desnitation: "etherhdr->ether_dhost);
  print_addr_eth("*** -> Received packet's desnitation: "etherhdr->ether_shost);

  /*
  uint16_t ethertype(uint8_t *buf) {
    sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
    return ntohs(ehdr->ether_type);
  }
  */
  uint16_t *payload = (packt + sizeof(sr_ethernet_hdr_t));

  if (ethertype(packet) == ethertype_arp) {
    printf("*** An ARP packet\n");

    sr_arp_hdr_t *arphdr = (sr_arp_hdr_t *) payload;

    if (arphdr->ar_hrd != arp_hrd_ethernet) {
      return;
    }

    if(arphdr->ar_op == arp_op_request) {
      /* ARP request*/

      struct sr_arpentry *cached = sr_arpcache_lookup(sr->cache, arphdr->ar_tip) {
        if (cached == NULL) {


        } else {
          free(cached);
        }
      }
    } else if (arphdr->ar_op == arp_op_reply) {
      /* TODO: ARP reply */
    }



  } else if (ethertype(packet) == ethertype_ip) {
    /* IP packet */
    sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)payload;

    if (sr_verifyiplength() == -1) {
      return;
    }
  }

  

  /*TODO: Verify checksum */

  /*TODO: Deal with ICMP messages
  if (iphdr->ip_p == ip_protocol_icmp) {

  }
  */

  /* fill in code here */

} /* end sr_ForwardPacket */

int sr_verifyiplength(sr_ip_hdr_t *headers)
{
  if (headers->ip_len < 20 && headers->ip_len > 60)
  {
    return -1;
  }
  if (cksum(headers, sizeof(sr_ip_hdr_t)) != headers->ip_sum ) {
    return -1;
  }
  return 0;
}
