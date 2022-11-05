/**********************************************************/
/*                                                        */
/* File: flow.h                                           */
/* Created: 2022-09-30                                    */
/* Last change: 2022-10-26                                */
/* Author: David Chocholaty <xchoch09@stud.fit.vutbr.cz>  */
/* Project: Project for the course ISA - variant 1        */
/*          - Generation of NetFlow data from captured    */
/*            network traffic.                            */
/* Description: Header file for NetFlow exporter          */
/*                                                        */
/**********************************************************/

#ifndef FLOW_H
#define FLOW_H

#include <stdint.h>
#include <stdio.h>

#include "netflow_v5.h"
#include "option.h"

/*
 * Function to handle needed operations before ending of flow program.
 * The needed operations is:
 * - free options allocated memory
 *
 * @param options         Pointer to pointer options storage.
 * @param netflow_records Pointer to netflow recording system.
 * @return                Status of function processing.
 */
uint8_t flow_epilogue (options_t options,
                       netflow_recording_system_t netflow_records);

/*
 * Main function of Netflow exporter.
 */
int main (int argc, char* argv[]);

#endif // FLOW_H
