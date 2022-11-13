/**********************************************************/
/*                                                        */
/* File: pcap.h                                           */
/* Author: David Chocholaty <xchoch09@stud.fit.vutbr.cz>  */
/* Project: Project for the course ISA - variant 1        */
/*          - Generation of NetFlow data from captured    */
/*            network traffic.                            */
/* Description: Header file for the pcap handling         */
/*                                                        */
/**********************************************************/

#ifndef FLOW_PCAP_H
#define FLOW_PCAP_H

#include <stdio.h>

#include "netflow_v5.h"

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
                                options_t options);

#endif // FLOW_PCAP_H
