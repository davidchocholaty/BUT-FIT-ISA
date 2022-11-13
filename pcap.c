/**********************************************************/
/*                                                        */
/* File: pcap.c                                           */
/* Created: 2022-10-26                                    */
/* Last change: 2022-10-26                                */
/* Author: David Chocholaty <xchoch09@stud.fit.vutbr.cz>  */
/* Project: Project for the course ISA - variant 1        */
/*          - Generation of NetFlow data from captured    */
/*            network traffic.                            */
/* Description: Pcap handling for the Netflow exporter    */
/*                                                        */
/**********************************************************/

#include "pcap.h"

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

#include "error.h"
#include "netflow_v5.h"

#define SIZE_ETHERNET (14)       // offset of Ethernet header to L3 protocol


/*
 * TODO
 */
uint8_t run_packets_processing (netflow_recording_system_t netflow_records,
                                netflow_sending_system_t sending_system,
                                options_t options)
{
    uint8_t status = NO_ERROR;
    int return_code;
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char* packet;
    struct pcap_pkthdr* header; // Has to be pointer because of pcap_next_ex
    pcap_t* handle;                 // file/device handler
    struct ether_header* eptr;

    char* input_stream = options->analyzed_input_source->file_name;

    //struct ip* my_ip;
    //const struct tcphdr* my_tcp;    // pointer to the beginning of TCP header
    //const struct udphdr* my_udp;    // pointer to the beginning of UDP header
    //u_int size_ip;

    if (input_stream == NULL)
    {
        // The name "-" is a synonym for stdin.
        input_stream = "-";
    }

    // Open the input file.
    if ((handle = pcap_open_offline(input_stream, errbuf)) == NULL)
    {
        return INVALID_INPUT_FILE_ERROR;
    }

    while (((return_code = pcap_next_ex(handle, &header, &packet)) > 0) && status == NO_ERROR)
    {
        // read the Ethernet header
        eptr = (struct ether_header *) packet;

        switch (ntohs(eptr->ether_type)){
            case ETHERTYPE_IP: // IPv4 packet
                status = process_packet(netflow_records, sending_system, header, packet, options);
                break;
            default:
                break;
        }
    }

    printf("end of processing packets\n");

    if (return_code < 0)
    {
        return PCAP_HANDLING_ERROR;
    }

    //printf("End of file reached ...\n");

    // close the capture device and deallocate resources
    pcap_close(handle);

    return status;
}
