/**********************************************************/
/*                                                        */
/* File: netflow_v5.h                                     */
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

#define MAX_FLOWS_NUMBER 30

typedef struct netflow_v5_header* netflow_v5_header_t;
typedef struct netflow_v5_flow_record* netflow_v5_flow_record_t;
typedef struct netflow_v5_key* netflow_v5_key_t;
typedef struct flow_node* flow_node_t;
typedef struct netflow_recording_system* netflow_recording_system_t;
typedef struct netflow_sending_system* netflow_sending_system_t;

struct bst_node; // Forward declaration

/*
 * Structure to store a NetFlow header.
 */
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

/*
 * Structure to store exported NetFlow record.
 */
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

/*
 * Structure to store NetFlow key.
 */
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

/*
 * Structure to store exported NetFlow records in format for a tree.
 */
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
    uint64_t cache_id;
};

/*
 * Structure to store the NetFlow recording system for the program.
 */
struct netflow_recording_system
{
    struct bst_node* tree;
    struct timeval* first_packet_time;
    struct timeval* last_packet_time;
    uint64_t* cached_flows_number;
    uint64_t* flows_statistics;
    uint64_t* sent_packets_statistics;
};

/*
 * Structure to store the sending system for the program.
 */
struct netflow_sending_system
{
    int* socket;
};

/*
 * Function for comparing flows by their keys.
 *
 * @param first_flow  First flow key.
 * @param second_flow Second flow key.
 * @return            The function returns 0 if the keys are equal, 1 if
 *                    a specific value is greater in first flow key,
 *                    -1 if a specific value is greater in second flow key.
 */
int compare_flows (netflow_v5_key_t first_flow, netflow_v5_key_t second_flow);

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
                      const uint16_t flows_number);

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
                              options_t options);

/*
 * Function for exporting all active cached flows and disposing of a tree.
 *
 * @param netflow_records   Pointer to pointer to the netflow recording system.
 * @param sending_system    Pointer to pointer to the sending system.
 * @return                  Status of function processing.
 */
uint8_t export_all_flows_dispose_tree (netflow_recording_system_t netflow_records,
                                       netflow_sending_system_t sending_system);

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
                   options_t options);

/*
 * Function for handling and processing packet data including calls of functions
 * responsible for managing flows.
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
                        options_t options);

#endif // FLOW_NETFLOW_V5_H
