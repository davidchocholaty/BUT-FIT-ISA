/**********************************************************/
/*                                                        */
/* File: pcap.c                                           */
/* Author: David Chocholaty <xchoch09@stud.fit.vutbr.cz>  */
/* Project: Project for the course ISA - variant 1        */
/*          - Generation of NetFlow data from captured    */
/*            network traffic.                            */
/* Description: Pcap handling for the Netflow exporter    */
/*                                                        */
/**********************************************************/

#include "pcap.h"

#include <pcap.h>
#include <time.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include "error.h"
#include "netflow_v5.h"

#define SIZE_ETHERNET (14)       // offset of Ethernet header to L3 protocol

/*
 * Function which runs reading the packet from the pcap files, processing
 * the packets and calling the function handling with the flows.
 *
 * @param netflow_records The storage of the netflow recording system
 *                        for the whole program.
 * @param sending_system  The storage of the sending system for the whole
 *                        program.
 * @param options         Pointer to options storage.
 * @return                Status of function processing.
 */
uint8_t run_packets_processing (netflow_recording_system_t netflow_records,
                                netflow_sending_system_t sending_system,
                                options_t options)
{
    uint8_t status = NO_ERROR;
    int return_code;
    char errbuf[PCAP_ERRBUF_SIZE];
    const u_char* packet;
    struct pcap_pkthdr* header; // Has to be pointer because of pcap_next_ex.
    pcap_t* handle;
    struct ether_header* eptr;

    char* input_stream = options->analyzed_input_source->file_name;

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
        // Read the Ethernet header.
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

    if (return_code < 0 && return_code != PCAP_ERROR_BREAK)
    {
        return PCAP_HANDLING_ERROR;
    }

    printf("End of file reached ...\n");

    // close the capture device and deallocate resources
    pcap_close(handle);

    return status;
}
