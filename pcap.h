/**********************************************************/
/*                                                        */
/* File: pcap.h                                           */
/* Created: 2022-10-26                                    */
/* Last change: 2022-10-26                                */
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
 * TODO
 */
void run_packets_processing (netflow_recording_system_t netflow_records,
                             options_t options);

#endif // FLOW_PCAP_H
