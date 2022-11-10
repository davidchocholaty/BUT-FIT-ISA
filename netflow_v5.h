/**********************************************************/
/*                                                        */
/* File: netflow_v5.h                                     */
/* Created: 2022-10-27                                    */
/* Last change: 2022-10-27                                */
/* Author: David Chocholaty <xchoch09@stud.fit.vutbr.cz>  */
/* Project: Project for the course ISA - variant 1        */
/*          - Generation of NetFlow data from captured    */
/*            network traffic.                            */
/* Description: Header file for the creating flows        */
/*                                                        */
/**********************************************************/

#ifndef FLOW_NETFLOW_V5_H
#define FLOW_NETFLOW_V5_H

#include <pcap.h>
#include <stdint.h>
#include <stdlib.h>

#include "option.h"
#include "tree.h"

typedef struct netflow_v5_header* netflow_v5_header_t;
typedef struct netflow_v5_flow_record* netflow_v5_flow_record_t;
typedef struct netflow_v5_key* netflow_v5_key_t;
typedef struct flow_node* flow_node_t;
typedef struct netflow_recording_system* netflow_recording_system_t;
typedef struct netflow_sending_system* netflow_sending_system_t;

struct bst_node; // Forward declaration

struct netflow_v5_header
{
    uint16_t version;
    uint16_t count;
    uint32_t sysuptime_ms;
    uint32_t unix_secs;
    uint32_t unix_nsecs;
    uint32_t flow_sequence;
    uint8_t engine_type;
    uint8_t engine_id;
    uint16_t sampling_interval;
};

struct netflow_v5_flow_record
{
    uint32_t src_addr;
    uint32_t dst_addr;
    uint32_t nexthop;
    uint16_t input;
    uint16_t output;
    uint32_t packets;
    uint32_t octets;
    uint32_t first;
    uint32_t last;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t pad1;
    uint8_t tcp_flags;
    uint8_t prot;
    uint8_t tos;
    uint16_t src_as;
    uint16_t dst_as;
    uint8_t src_mask;
    uint8_t dst_mask;
    uint16_t pad2;
};

struct netflow_v5_key
{
    uint16_t input;
    uint32_t src_addr;
    uint32_t dst_addr;
    uint8_t prot;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t tos;
};

struct flow_node
{
    uint32_t src_addr;
    uint32_t dst_addr;
    uint32_t packets;
    uint32_t octets;
    struct timeval* first;
    struct timeval* last;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t tcp_flags;
    uint8_t prot;
    uint8_t tos;
};

struct netflow_recording_system
{
    struct bst_node* tree;
    struct timeval* first_packet_time;
    struct timeval* last_packet_time;
};

struct netflow_sending_system
{
    int* socket;
};

uint8_t process_packet (netflow_recording_system_t netflow_records,
                        netflow_sending_system_t sending_system,
                        const struct pcap_pkthdr* header,
                        const u_char* packet,
                        options_t options);

int compare_flows (netflow_v5_key_t first_flow, netflow_v5_key_t second_flow);

uint8_t export_flow (netflow_recording_system_t netflow_records,
                     netflow_sending_system_t sending_system,
                     flow_node_t flow_export);

void export_all_flows_dispose_tree (netflow_recording_system_t netflow_records,
                                    netflow_sending_system_t sending_system);

uint8_t connect_socket (int* sock, char* source);

void disconnect_socket (const int* sock);

#endif // FLOW_NETFLOW_V5_H
