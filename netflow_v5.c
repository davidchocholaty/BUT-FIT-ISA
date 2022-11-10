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
#define MAX_BUFFER_SIZE 1024                // buffer length
#define MAX_PACKET_SIZE (sizeof(struct netflow_v5_header) + \
                         sizeof(struct netflow_v5_flow_record))

uint8_t export_flow (netflow_v5_flow_record_t flow_export,
                     netflow_sending_system_t sending_system)
{
    const uint16_t version = 5;
    const uint16_t flows_count = 1;
    size_t offset;
    size_t packet_size;
    ssize_t return_code;
    uint8_t packet[MAX_PACKET_SIZE];
    netflow_v5_header_t header;
    netflow_v5_flow_record_t flow_record;

    memset (&packet, '\0', sizeof (packet));

    header = (netflow_v5_header_t) packet;

    header->version = htons(version);
    header->count = htons(flows_count);
    // header->sysuptime_ms // TODO
    // header->unix_secs = // TODO
    // header->unix_nsecs = // TODO
    // header->flow_sequence = // TODO
    header->sampling_interval = htons(0x01 << 14);
    // header->engine_type and header->engine_id are left zero.

    offset = sizeof(*header);

    flow_record = (netflow_v5_flow_record_t) (packet + offset);

    flow_record->src_addr = flow_export->src_addr;
    flow_record->dst_addr = flow_export->dst_addr;
    flow_record->packets = flow_export->packets;
    flow_record->octets = htonl(flow_export->octets);
    // TODO first
    // TODO last
    flow_record->src_port = flow_export->src_port;
    flow_record->dst_port = flow_export->dst_port;
    flow_record->tcp_flags = flow_export->tcp_flags;
    flow_record->prot = flow_export->prot;
    flow_record->tos = flow_export->tos;
    // The rest of values are left zero.


    packet_size = offset + sizeof(*flow_record);

    // Send packet
    return_code = send(*(sending_system->socket), packet, packet_size, 0);

    if (return_code == -1)
    {
        // Send failed.
        return PACKET_SENDING_ERROR;
    }
    else if ((size_t)return_code != packet_size)
    {
        // Buffer written partially.
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

    return NO_ERROR;
}

void export_all_flows_dispose_tree (netflow_recording_system_t netflow_records,
                                    netflow_sending_system_t sending_system)
{
    bst_node_t* tree = &(netflow_records->tree);

    if (tree != NULL)
    {
        bst_export_all(tree, sending_system);
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
/*
void send_netflow ()
{
    int sock;                        // socket descriptor
    int msg_size, i;
    struct sockaddr_in server, from; // address structures of the server and the client
    struct hostent *servent;         // network host entry required by gethostbyname()
    socklen_t len, fromlen;
    char buffer[BUFFER];

    memset(&server,0,sizeof(server)); // erase the server structure
    server.sin_family = AF_INET;

    // make DNS resolution of the first parameter using gethostbyname()
    // argv[1] -> address
    // argv[2] -> port
    if ((servent = gethostbyname(argv[1])) == NULL) // check the first parameter
        errx(1,"gethostbyname() failed\n");

    // copy the first parameter to the server.sin_addr structure
    memcpy(&server.sin_addr,servent->h_addr,servent->h_length);

    server.sin_port = htons(atoi(argv[2]));        // server port (network byte order)

    if ((sock = socket(AF_INET , SOCK_DGRAM , 0)) == -1)   //create a client socket
        err(1,"socket() failed\n");

    printf("* Server socket created\n");

    len = sizeof(server);
    fromlen = sizeof(from);

    printf("* Creating a connected UDP socket using connect()\n");
    // create a connected UDP socket
    if (connect(sock, (struct sockaddr *)&server, sizeof(server))  == -1)
        err(1, "connect() failed");

    //send data to the server
    while((msg_size=read(STDIN_FILENO,buffer,BUFFER)) > 0)
        // read input data from STDIN (console) until end-of-line (Enter) is pressed
        // when end-of-file (CTRL-D) is received, n == 0
    {
        i = send(sock,buffer,msg_size,0);     // send data to the server
        if (i == -1)                   // check if data was sent correctly
            err(1,"send() failed");
        else if (i != msg_size)
            err(1,"send(): buffer written partially");

        // obtain the local IP address and port using getsockname()
        if (getsockname(sock,(struct sockaddr *) &from, &len) == -1)
            err(1,"getsockname() failed");

        printf("* Data sent from %s, port %d (%d) to %s, port %d (%d)\n",inet_ntoa(from.sin_addr), ntohs(from.sin_port), from.sin_port, inet_ntoa(server.sin_addr),ntohs(server.sin_port), server.sin_port);

        // read the answer from the server
        if ((i = recv(sock,buffer, BUFFER,0)) == -1)
            err(1,"recv() failed");
        else if (i > 0){
            // obtain the remote IP adddress and port from the server (cf. recfrom())
            if (getpeername(sock, (struct sockaddr *)&from, &fromlen) != 0)
                err(1,"getpeername() failed\n");

            printf("* UDP packet received from %s, port %d\n",inet_ntoa(from.sin_addr),ntohs(from.sin_port));
            printf("%.*s",i,buffer);                   // print the answer
        }
    }
    // reading data until end-of-file (CTRL-D)

    if (msg_size == -1)
        err(1,"reading failed");

    close(sock);
    printf("* Closing the client socket ...\n");

    return 0;
}
*/
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
                        netflow_sending_system_t sending_system,
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
    bst_export_expired(&(netflow_records->tree), sending_system, packet_time_stamp, options);

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
