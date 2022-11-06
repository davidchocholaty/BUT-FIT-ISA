/**********************************************************/
/*                                                        */
/* File: netflow_v5.c                                     */
/* Created: 2022-10-27                                    */
/* Last change: 2022-10-27                                */
/* Author: David Chocholaty <xchoch09@stud.fit.vutbr.cz>  */
/* Project: Project for the course ISA - variant 1        */
/*          - Generation of NetFlow data from captured    */
/*            network traffic.                            */
/* Description: Creating flows in the Netflow exporter    */
/*                                                        */
/**********************************************************/

#include "netflow_v5.h"

#include <stdlib.h>



#include <pcap.h>
#include <netinet/ether.h>
#include <time.h>

// TODO maybe later delete
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

#include <string.h>

#include "error.h"
#include "memory.h"
#include "tree.h"

#define SIZE_ETHERNET (14)       // offset of Ethernet header to L3 protocol

void export_flow (netflow_v5_flow_record_t flow)
{
    static int i = 1;
    flow->tos = flow->tos;
    printf("exporting flow %d\n", i);
    i++;
}

uint8_t find_flow (bst_node_t* flows_tree,
                   netflow_v5_key_t packet_key,
                   const struct timeval* packet_time_stamp,
                   const uint16_t packet_layer_3_bytes,
                   const uint8_t packet_tcp_flags)
{
    uint8_t status = NO_ERROR;
    netflow_v5_flow_record_t flow = NULL;

    //----------------------------------------------
    //static int p = 1;

    //printf("packet: %d\n", p);

    //p++;
    //----------------------------------------------

    if (!bst_search(*flows_tree, packet_key, &flow))
    {
        // Matching flow does not exist.
        // A new flow will be created and inserted.

        //----------------------------------------------
        //static int i = 1;

        //printf("New flow: %d\n", i);

        //i++;
        //----------------------------------------------

        netflow_v5_flow_record_t new_flow = NULL;
        netflow_v5_key_t new_key = NULL;

        status = allocate_netflow_key(&new_key);

        if (status != EXIT_SUCCESS)
        {
            return MEMORY_HANDLING_ERROR;
        }

        status = allocate_netflow_record(&new_flow);

        if (status != EXIT_SUCCESS)
        {
            return MEMORY_HANDLING_ERROR;
        }

        // Set flow key values.
        new_key->src_addr = packet_key->src_addr;
        new_key->dst_addr = packet_key->dst_addr;

        new_key->src_port = packet_key->src_port;
        new_key->dst_port = packet_key->dst_port;

        new_key->prot = packet_key->prot;
        new_key->tos = packet_key->tos;

        // Unknown set as zero.
        new_key->input = 0;

        // Set flow record values.
        new_flow->src_addr = packet_key->src_addr;
        new_flow->dst_addr = packet_key->dst_addr;

        new_flow->src_port = packet_key->src_port;
        new_flow->dst_port = packet_key->dst_port;

        new_flow->prot = packet_key->prot;
        new_flow->tos = packet_key->tos;

        new_flow->tcp_flags |= packet_tcp_flags;
        // TODO later expiration because TH_RST or TH_FIN


        // Unknown set as zero.
        new_flow->nexthop = 0;
        new_flow->input = 0;
        new_flow->output = 0;
        new_flow->src_as = 0;
        new_flow->dst_as = 0;
        new_flow->pad1 = 0;
        new_flow->pad2 = 0;


        // Set other specific values.
        new_flow->packets = 1;
        new_flow->octets = packet_layer_3_bytes;

        // TODO masks
        new_flow->src_mask = 0;
        new_flow->dst_mask = 0;

        memcpy(&(new_flow->first), packet_time_stamp, sizeof(new_flow->first));
        memcpy(&(new_flow->last), packet_time_stamp, sizeof(new_flow->last));

        // Add flow into the flows tree.
        status = bst_insert(flows_tree, new_key, new_flow);
    }
    else
    {
        // Matching flow does was found.
        // Update flow record.
        flow->packets += 1;
        flow->octets += flow->octets + packet_layer_3_bytes;
        flow->tcp_flags |= packet_tcp_flags;

        memcpy(&(flow->last), packet_time_stamp, sizeof(flow->last));
    }

    return status;
}

uint8_t process_packet (netflow_recording_system_t netflow_records,
                        const struct pcap_pkthdr* header,
                        const u_char* packet,
                        options_t options)
{
    struct ip* my_ip = NULL;
    const struct tcphdr* my_tcp = NULL;    // pointer to the beginning of TCP header
    const struct udphdr* my_udp = NULL;    // pointer to the beginning of UDP header
    netflow_v5_key_t packet_key = NULL;
    u_int size_ip = 0;
    uint8_t tcp_flags = 0;
    uint8_t status = NO_ERROR;
    uint16_t packet_layer_3_bytes = header->len - SIZE_ETHERNET;
    // Time stamp of an actual received packet
    struct timeval packet_time_stamp = header->ts;
/*
    if (netflow_records->tree == NULL)
    {
        printf("process_packet: tree is null\n");
    }
*/
    // Check timers with actual packet timestamp value
    // and export the expired flows.
    bst_export_expired(&(netflow_records->tree), packet_time_stamp, options);

    status = allocate_netflow_key(&packet_key);

    if (status != NO_ERROR)
    {
        return MEMORY_HANDLING_ERROR;
    }

    my_ip = (struct ip*) (packet+SIZE_ETHERNET);        // skip Ethernet header
    size_ip = my_ip->ip_hl*4;                           // length of IP header

    packet_key->input = 0;
    packet_key->tos = my_ip->ip_tos;

    /********* IP addresses *********/
    // TODO maybe some check on ip address
    packet_key->src_addr = my_ip->ip_src.s_addr;
    packet_key->dst_addr = my_ip->ip_dst.s_addr;

    /********* Protocol *********/
    packet_key->prot = my_ip->ip_p;

    switch (my_ip->ip_p){
        case IPPROTO_ICMP: // ICMP protocol (ICMPv4)
            packet_key->src_port = 0;
            packet_key->dst_port = 0;

            // TODO packet_layer_3_bytes
            find_flow(&(netflow_records->tree),
                      packet_key,
                      &packet_time_stamp,
                      packet_layer_3_bytes,
                      tcp_flags);
            break;
        case IPPROTO_TCP: // TCP protocol
            my_tcp = (struct tcphdr *) (packet + SIZE_ETHERNET + size_ip); // pointer to the TCP header

            packet_key->src_port = ntohs(my_tcp->th_sport);
            packet_key->dst_port = ntohs(my_tcp->th_dport);

            tcp_flags = my_tcp->th_flags;

            // TODO packet_layer_3_bytes
            find_flow(&(netflow_records->tree),
                      packet_key,
                      &packet_time_stamp,
                      packet_layer_3_bytes,
                      tcp_flags);
            break;
        case IPPROTO_UDP: // UDP protocol
            my_udp = (struct udphdr *) (packet+SIZE_ETHERNET+size_ip); // pointer to the UDP header

            packet_key->src_port = ntohs(my_udp->uh_sport);
            packet_key->dst_port = ntohs(my_udp->uh_dport);

            // TODO packet_layer_3_bytes
            find_flow(&(netflow_records->tree),
                      packet_key,
                      &packet_time_stamp,
                      packet_layer_3_bytes,
                      tcp_flags);
            break;
        default:
            break;
    }

    free_netflow_key(&packet_key);

    return 0;
}

int compare_flows (netflow_v5_key_t first_flow, netflow_v5_key_t second_flow)
{
    if (first_flow == NULL)
    {
        printf("first flow is NULL\n");
    }

    if (first_flow == NULL)
    {
        printf("first flow is NULL\n");
    }

    if (first_flow->input != second_flow->input)
    {
        return (first_flow->input > second_flow->input) ? 1 : -1;
    }

    if (first_flow->src_addr != second_flow->src_addr)
    {
        return (first_flow->src_addr > second_flow->src_addr) ? 1 : -1;
    }

    if (first_flow->dst_addr != second_flow->dst_addr)
    {
        return (first_flow->dst_addr > second_flow->dst_addr) ? 1 : -1;
    }

    if (first_flow->prot != second_flow->prot)
    {
        return (first_flow->prot > second_flow->prot) ? 1 : -1;
    }

    if (first_flow->src_port != second_flow->src_port)
    {
        return (ntohs(first_flow->src_port) > ntohs(second_flow->src_port)) ? 1 : -1;
    }

    if (first_flow->dst_port != second_flow->dst_port)
    {
        return (ntohs(first_flow->dst_port) > ntohs(second_flow->dst_port)) ? 1 : -1;
    }

    if (first_flow->tos != second_flow->tos)
    {
        return (first_flow->tos > second_flow->tos) ? 1 : -1;
    }

    return 0;
}
