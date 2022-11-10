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
#include <unistd.h>

#include "util.h"

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
#define MAX_PACKET_SIZE (sizeof(struct netflow_v5_header) + \
                         sizeof(struct flow_node))

uint8_t export_flow (netflow_recording_system_t netflow_records,
                     netflow_sending_system_t sending_system,
                     flow_node_t flow_export)
{
    static uint64_t flow_sequence_number = 0;
    const uint16_t version = 5;
    const uint16_t flows_count = 1;
    size_t offset;
    size_t packet_size;
    ssize_t return_code;
    uint8_t packet[MAX_PACKET_SIZE];
    netflow_v5_header_t header;
    netflow_v5_flow_record_t flow_record;

    memset (&packet, '\0', sizeof(packet));

    header = (netflow_v5_header_t) packet;

    header->version = htons(version);
    header->count = htons(flows_count);
    // TODO fix time difference in one
    header->sysuptime_ms = htonl(get_timeval_ms(netflow_records->last_packet_time,
                                                netflow_records->first_packet_time));
    header->unix_secs = htonl(netflow_records->last_packet_time->tv_sec);
    header->unix_nsecs = htonl(netflow_records->last_packet_time->tv_usec * 1000);
    header->flow_sequence = htonl(flow_sequence_number);
    header->sampling_interval = htons(0x01 << 14);
    // header->engine_type and header->engine_id are left zero.

    offset = sizeof(*header);

    flow_record = (netflow_v5_flow_record_t) (packet + offset);

    flow_record->src_addr = flow_export->src_addr;
    flow_record->dst_addr = flow_export->dst_addr;
    flow_record->packets = htonl(flow_export->packets);
    flow_record->octets = htonl(flow_export->octets);

    flow_record->first = htonl(get_timeval_ms(flow_export->first,
                                              netflow_records->first_packet_time));
    flow_record->last = htonl(get_timeval_ms(flow_export->last,
                                             netflow_records->first_packet_time));

    flow_record->src_port = flow_export->src_port;
    flow_record->dst_port = flow_export->dst_port;
    flow_record->tcp_flags = flow_export->tcp_flags;
    flow_record->prot = flow_export->prot;
    flow_record->tos = flow_export->tos;
    // The rest of values are left zero.

    packet_size = offset + sizeof(*flow_record);

    // Send packet
    return_code = send(*(sending_system->socket), packet, packet_size, 0);

    if (return_code == -1 || (size_t)return_code != packet_size)
    {
        // Send failed.
        return PACKET_SENDING_ERROR;
    }

/*
    // Read the answer from the server.
    return_code = recv(*(sending_system->socket), packet, MAX_BUFFER_SIZE, 0);

    if (return_code == -1)
    {
        // Recv failed.
        return PACKET_SENDING_ERROR;
    }
*/


    static int i = 1;
    printf("exporting flow %d\n", i);
    i++;

    flow_sequence_number++;

    return NO_ERROR;
}

void export_all_flows_dispose_tree (netflow_recording_system_t netflow_records,
                                    netflow_sending_system_t sending_system)
{
    bst_node_t* tree = &(netflow_records->tree);

    if (tree != NULL)
    {
        bst_export_all(netflow_records , sending_system, tree);
        bst_dispose(tree);
    }
}

uint8_t connect_socket (int* sock, char* source)
{
    struct sockaddr_in server;//, from; // address structures of the server and the client
    struct hostent *servent;         // network host entry required by gethostbyname()

    uint8_t status = NO_ERROR;
    char* source_name = NULL;
    char* source_port = NULL;
    char* end;

    long int port_numeric;

    status = parse_name_port(source, &source_name, &source_port);

    printf("name: %s\n", source_name);
    printf("port: %s\n", source_port);

    if (status != NO_ERROR)
    {
        return status;
    }

    memset(&server, 0, sizeof(server)); // erase the server structure
    server.sin_family = AF_INET;

    // make DNS resolution of the first parameter using gethostbyname()

    // check the first parameter
    if ((servent = gethostbyname(source_name)) == NULL)
    {
        free_string(&source_name);
        free_string(&source_port);

        return SOCKET_ERROR;
    }

    // copy the first parameter to the server.sin_addr structure
    memcpy(&server.sin_addr, servent->h_addr, servent->h_length);

    if (source_port != NULL)
    {
        port_numeric = strtol(source_port, &end, 10);

        if (port_numeric == 0L)
        {
            return INVALID_OPTION_ERROR;
        }

        server.sin_port = htons((uint16_t)port_numeric);        // server port (network byte order)
    }

    //create a client socket
    if ((*sock = socket(AF_INET , SOCK_DGRAM , 0)) == -1)
    {
        return SOCKET_ERROR;
    }

    printf("* Server socket created\n");

    //len = sizeof(server);
    //fromlen = sizeof(from);

    printf("* Creating a connected UDP socket using connect()\n");
    // create a connected UDP socket
    if (connect(*sock, (struct sockaddr *)&server, sizeof(server))  == -1)
    {
        return SOCKET_ERROR;
    }

    free_string(&source_name);
    free_string(&source_port);

    return NO_ERROR;
}

void disconnect_socket (const int* sock)
{
    close(*sock);
    printf("* Closing the client socket ...\n");
}

uint8_t find_flow (bst_node_t* flows_tree,
                   netflow_v5_key_t packet_key,
                   const struct timeval* packet_time_stamp,
                   const uint16_t packet_layer_3_bytes,
                   const uint8_t packet_tcp_flags)
{
    uint8_t status = NO_ERROR;
    flow_node_t flow = NULL;

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

        new_flow->tcp_flags |= packet_tcp_flags;
        // TODO later expiration because TH_RST or TH_FIN

        // Set other specific values.
        new_flow->packets = 1;
        new_flow->octets = packet_layer_3_bytes;

        memcpy(new_flow->first, packet_time_stamp, sizeof(*(new_flow->first)));
        memcpy(new_flow->last, packet_time_stamp, sizeof(*(new_flow->last)));

        // Add flow into the flows tree.
        status = bst_insert(flows_tree, new_key, new_flow);
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

uint8_t process_packet (netflow_recording_system_t netflow_records,
                        netflow_sending_system_t sending_system,
                        const struct pcap_pkthdr* header,
                        const u_char* packet,
                        options_t options)
{
    static uint64_t packet_number = 0;

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

    printf("packet number: %lu\n", packet_number);

    if (packet_number == 0)
    {
        memcpy(netflow_records->first_packet_time,
               &packet_time_stamp,
               sizeof(*(netflow_records->first_packet_time)));
    }

    memcpy(netflow_records->last_packet_time,
           &packet_time_stamp,
           sizeof(*(netflow_records->last_packet_time)));

/*
    if (netflow_records->tree == NULL)
    {
        printf("process_packet: tree is null\n");
    }
*/

    // Check timers with actual packet timestamp value
    // and export the expired flows.
    bst_export_expired(netflow_records , sending_system, &(netflow_records->tree), packet_time_stamp, options);

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

    packet_number++;

    return NO_ERROR;
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
