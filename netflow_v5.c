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

#include <arpa/inet.h>
#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#define __FAVOR_BSD // For Merlin server.
#include <netinet/tcp.h>
#include <netinet/udp.h>
#undef __FAVOR_BSD // For Merlin server.

#include "error.h"
#include "memory.h"
#include "tree.h"
#include "util.h"

#define SIZE_ETHERNET (14)  // Offset of Ethernet header to L3 protocol.

/*
 * Function for comparing flows by their keys.
 *
 * @param first_flow  First flow key.
 * @param second_flow Second flow key.
 * @return            The function returns 0 if the keys are equal, 1 if
 *                    a specific value is greater in first flow key,
 *                    -1 if a specific value is greater in second flow key.
 */
int compare_flows (netflow_v5_key_t first_flow, netflow_v5_key_t second_flow)
{
    int return_code;

    if (first_flow->input != second_flow->input)
    {
        return (first_flow->input > second_flow->input) ? 1 : -1;
    }

    return_code = memcmp(&(first_flow->src_addr),
                         &(second_flow->src_addr),
                         sizeof(first_flow->src_addr));

    if (return_code != 0)
    {
        return (return_code > 0) ? 1 : -1;
    }

    return_code = memcmp(&(first_flow->dst_addr),
                         &(second_flow->dst_addr),
                         sizeof(first_flow->dst_addr));

    if (return_code != 0)
    {
        return (return_code > 0) ? 1 : -1;
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

/*
 * Function for exporting flows to collector.
 *
 * @param netflow_records Pointer to pointer to the netflow recording system.
 * @param sending_system  Pointer to pointer to the sending system.
 * @param flows           An array of flows to export.
 * @param flows_number    The number of flows in the array of flows to export.
 * @return                Status of function processing.
 */
uint8_t export_flows (netflow_recording_system_t netflow_records,
                      netflow_sending_system_t sending_system,
                      flow_node_t* flows,
                      const uint16_t flows_number)
{
    static uint32_t flow_sequence_number = 0;
    const uint16_t version = 5;
    const size_t packet_size = (size_t) (sizeof(struct netflow_v5_header) +
            flows_number * sizeof(struct netflow_v5_flow_record));
    size_t offset;
    ssize_t return_code;
    uint8_t packet[packet_size];
    netflow_v5_header_t header;
    netflow_v5_flow_record_t flow_record;

    memset (&packet, '\0', sizeof(packet));

    header = (netflow_v5_header_t) packet;

    header->version = htons(version);
    header->count = htons(flows_number);
    header->sysuptime_ms = htonl(get_timeval_ms(netflow_records->last_packet_time,
                                                netflow_records->first_packet_time));
    header->unix_secs = htonl(netflow_records->last_packet_time->tv_sec);
    header->unix_nsecs = htonl(netflow_records->last_packet_time->tv_usec * 1000);
    header->flow_sequence = htonl(flow_sequence_number);
    // header->engine_type, header->engine_id and header->sampling_interval
    // are left zero.

    for (uint16_t i = 0; i < flows_number; i++)
    {
        offset = sizeof(*header) + i * sizeof(*flow_record);

        flow_record = (netflow_v5_flow_record_t) (packet + offset);

        flow_record->src_addr = flows[i]->src_addr;
        flow_record->dst_addr = flows[i]->dst_addr;
        flow_record->packets = htonl(flows[i]->packets);
        flow_record->octets = htonl(flows[i]->octets);

        flow_record->first = htonl(get_timeval_ms(flows[i]->first,
                                                  netflow_records->first_packet_time));
        flow_record->last = htonl(get_timeval_ms(flows[i]->last,
                                                 netflow_records->first_packet_time));

        flow_record->src_port = htons(flows[i]->src_port);
        flow_record->dst_port = htons(flows[i]->dst_port);
        flow_record->tcp_flags = flows[i]->tcp_flags;
        flow_record->prot = flows[i]->prot;
        flow_record->tos = flows[i]->tos;
        // The rest of values are left zero.
    }

    // Send packet
    return_code = send(*(sending_system->socket), packet, packet_size, 0);

    if (return_code == -1 || (size_t)return_code != packet_size)
    {
        // Send failed.
        return PACKET_SENDING_ERROR;
    }

    flow_sequence_number += flows_number;

    // Update the cached flows number.
    *(netflow_records->cached_flows_number) -= (uint64_t)flows_number;

    // Update statistics.
    *(netflow_records->flows_statistics) += (uint64_t)flows_number;
    *(netflow_records->sent_packets_statistics) += 1;

    return NO_ERROR;
}

/*
 * Function for exporting expired flows to collector.
 *
 * @param netflow_records   Pointer to pointer to the netflow recording system.
 * @param sending_system    Pointer to pointer to the sending system.
 * @param packet_time_stamp Current packet time stamp.
 * @param options           Pointer to options storage.
 * @return                  Status of function processing.
 */
uint8_t export_expired_flows (netflow_recording_system_t netflow_records,
                              netflow_sending_system_t sending_system,
                              struct timeval* packet_time_stamp,
                              options_t options)
{
    uint8_t status;
    bst_node_t expired_flows_tree;

    bst_init(&expired_flows_tree);

    // Add expired flows into the expired flows tree.
    status = bst_find_expired(&(netflow_records->tree),
                              &expired_flows_tree,
                              packet_time_stamp,
                              options);

    if (status != NO_ERROR)
    {
        return status;
    }

    // Export all flows from the expired flows tree by the oldest one.
    status = bst_export_all(netflow_records, sending_system, &expired_flows_tree);

    if (status != NO_ERROR)
    {
        bst_dispose(&(netflow_records->tree));
    }

    return status;
}

/*
 * Function for exporting all active cached flows and disposing of a tree.
 *
 * @param netflow_records   Pointer to pointer to the netflow recording system.
 * @param sending_system    Pointer to pointer to the sending system.
 * @return                  Status of function processing.
 */
uint8_t export_all_flows_dispose_tree (netflow_recording_system_t netflow_records,
                                       netflow_sending_system_t sending_system)
{
    uint8_t status = NO_ERROR;
    bst_node_t* tree = &(netflow_records->tree);

    if (tree != NULL)
    {
        status = bst_export_all(netflow_records , sending_system, tree);
    }

    return status;
}

/*
 * Function for handling the new packet. The function finds the flow
 * with the same parameters as the packet or creates a new one.
 *
 * @param netflow_records      Pointer to pointer to the netflow recording
 *                             system.
 * @param sending_system       Pointer to pointer to the sending system.
 * @param packet_key           The NetFlow key format of a packet.
 * @param packet_time_stamp    Current packet time stamp.
 * @param packet_layer_3_bytes The number of Layer 3 bytes in the packet.
 * @param packet_tcp_flags     TCP flags of the current packet.
 * @param options              Pointer to options storage.
 * @return                     Status of function processing.
 */
uint8_t find_flow (netflow_recording_system_t netflow_records,
                   netflow_sending_system_t sending_system,
                   netflow_v5_key_t packet_key,
                   const struct timeval* packet_time_stamp,
                   const uint16_t packet_layer_3_bytes,
                   const uint8_t packet_tcp_flags,
                   options_t options)
{
    static const uint64_t id_mask = UINT64_MAX >> 1;
    static uint64_t cache_id = 0;
    uint8_t status = NO_ERROR;
    flow_node_t flow = NULL;
    bst_node_t* flows_tree = &(netflow_records->tree);

    if (!bst_search(*flows_tree, packet_key, &flow))
    {
        // Matching flow does not exist.
        // A new flow will be created and inserted.
        flow_node_t new_flow = NULL;
        netflow_v5_key_t new_key = NULL;

        status = allocate_netflow_key(&new_key);

        if (status != EXIT_SUCCESS)
        {
            return MEMORY_HANDLING_ERROR;
        }

        status = allocate_flow_node(&new_flow);

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

        new_flow->tcp_flags = packet_tcp_flags;

        // Set other specific values.
        new_flow->packets = 1;
        new_flow->octets = packet_layer_3_bytes;

        memcpy(new_flow->first, packet_time_stamp, sizeof(*(new_flow->first)));
        memcpy(new_flow->last, packet_time_stamp, sizeof(*(new_flow->last)));

        *(netflow_records->cached_flows_number) += 1;

        if (*(netflow_records->cached_flows_number) >
        options->cached_entries_number->entries_number)
        {
            status = bst_export_oldest(netflow_records, sending_system, flows_tree);
        }

        if (status == NO_ERROR)
        {
            new_flow->cache_id = cache_id;

            // Add flow into the flows tree.
            status = bst_insert(flows_tree, new_key, new_flow);

            // Update the next id value.
            cache_id = (cache_id + 1) & id_mask;
        }
        else
        {
            free_netflow_key(&new_key);
            free_flow_node(&new_flow);

            bst_dispose(flows_tree);
        }
    }
    else
    {
        // Matching flow does was found.
        // Update flow record.
        flow->packets += 1;
        flow->octets += packet_layer_3_bytes;
        flow->tcp_flags |= packet_tcp_flags;

        memcpy(flow->last, packet_time_stamp, sizeof(*(flow->last)));
    }

    return status;
}

/*
 * Function for handling and processing packet data including calls of functions
 * responsible for managing flows.
 *
 * This function is inspired of the following source:
 *
 * Source: Course ISA at BUT FIT 2022 (https://www.fit.vut.cz/study/course/ISA/.en)
 * Lecture: 3. Multicast. Link layer data processing.
 * File: read-pcap.c
 * Year of creation: 2020
 * Year of the last file modification: 2020
 * Author: Matoušek Petr, doc. Ing., Ph.D., M.A. (https://www.fit.vut.cz/person/matousp/.en)
 *
 * @param netflow_records   Pointer to pointer to the netflow recording system.
 * @param sending_system    Pointer to pointer to the sending system.
 * @param header            Packet header data.
 * @param packet            Packet body data.
 * @param options           Pointer to options storage.
 * @return                  Status of function processing.
 */
uint8_t process_packet (netflow_recording_system_t netflow_records,
                        netflow_sending_system_t sending_system,
                        const struct pcap_pkthdr* header,
                        const u_char* packet,
                        options_t options)
{
    static bool first_packet = true;
    struct ip* my_ip = NULL;
    const struct tcphdr* my_tcp = NULL; // Pointer to the beginning of TCP header.
    const struct udphdr* my_udp = NULL; // Pointer to the beginning of UDP header.
    const struct icmp* my_icmp = NULL;
    netflow_v5_key_t packet_key = NULL;
    u_int size_ip = 0;
    uint8_t tcp_flags = 0;
    uint8_t status = NO_ERROR;
    uint16_t packet_layer_3_bytes = header->len - SIZE_ETHERNET;
    // Time stamp of an actual received packet
    struct timeval packet_time_stamp = header->ts;

    if (first_packet)
    {
        memcpy(netflow_records->first_packet_time,
               &packet_time_stamp,
               sizeof(*(netflow_records->first_packet_time)));

        first_packet = false;
    }

    memcpy(netflow_records->last_packet_time,
           &packet_time_stamp,
           sizeof(*(netflow_records->last_packet_time)));

    // Check timers with actual packet timestamp value
    // and export the expired flows.
    status = export_expired_flows(netflow_records,
                                  sending_system,
                                  &packet_time_stamp,
                                  options);

    if (status != NO_ERROR)
    {
        return status;
    }

    status = allocate_netflow_key(&packet_key);

    if (status != NO_ERROR)
    {
        return MEMORY_HANDLING_ERROR;
    }

    my_ip = (struct ip*) (packet+SIZE_ETHERNET); // Skip Ethernet header.
    size_ip = my_ip->ip_hl*4;                    // Length of IP header.

    packet_key->input = 0;
    packet_key->tos = my_ip->ip_tos;

    /********* IP addresses *********/
    packet_key->src_addr = my_ip->ip_src.s_addr;
    packet_key->dst_addr = my_ip->ip_dst.s_addr;

    /********* Protocol *********/
    packet_key->prot = my_ip->ip_p;

    switch (my_ip->ip_p){
        case IPPROTO_ICMP: // ICMP protocol (ICMPv4)
            my_icmp = (struct icmp *) (packet + SIZE_ETHERNET + size_ip);

            packet_key->src_port = 0;

            // The calculation formula is inspired of the following source:
            //
            // Source: https://marc.info/?l=netflow-tools&m=139653872523808&w=2
            // Author: Damien Miller (https://github.com/djmdjm)
            // Contributor: Steve Snodgrass
            // Project: netflow-tools (Softflowd)
            // Date of the modification: 2006-03-14
            // Copyright: Copyright 2002-2006 Damien Miller <djm@mindrot.org> All rights reserved.
            packet_key->dst_port = my_icmp->icmp_type * 256 + my_icmp->icmp_code;

            status = find_flow(netflow_records,
                               sending_system,
                               packet_key,
                               &packet_time_stamp,
                               packet_layer_3_bytes,
                               tcp_flags,
                               options);
            break;
        case IPPROTO_TCP: // TCP protocol
            // Pointer to the TCP header.
            my_tcp = (struct tcphdr *) (packet + SIZE_ETHERNET + size_ip);

            packet_key->src_port = ntohs(my_tcp->th_sport);
            packet_key->dst_port = ntohs(my_tcp->th_dport);

            tcp_flags = my_tcp->th_flags;

            status = find_flow(netflow_records,
                               sending_system,
                               packet_key,
                               &packet_time_stamp,
                               packet_layer_3_bytes,
                               tcp_flags,
                               options);
            break;
        case IPPROTO_UDP: // UDP protocol
            // Pointer to the UDP header.
            my_udp = (struct udphdr *) (packet+SIZE_ETHERNET+size_ip);

            packet_key->src_port = ntohs(my_udp->uh_sport);
            packet_key->dst_port = ntohs(my_udp->uh_dport);

            status = find_flow(netflow_records,
                               sending_system,
                               packet_key,
                               &packet_time_stamp,
                               packet_layer_3_bytes,
                               tcp_flags,
                               options);
            break;
        default:
            break;
    }

    free_netflow_key(&packet_key);

    return status;
}
