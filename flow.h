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
 * Function for connecting socket to establishing a connection
 * with a NetFlow collector.
 *
 * @param sock   Pointer to socket.
 * @param source String containing a collector name and possibly port.
 * @return       Status of function processing.
 */
uint8_t connect_socket (int* sock, char* source);

/*
 * Function for disconnecting the created socket.
 *
 * @param sock Pointer to socket.
 */
void disconnect_socket (const int* sock);

/*
 * Function to handle needed operations before ending of flow program.
 * The needed operations is:
 * - free options allocated memory
 *
 * @param netflow_records Pointer to NetFlow recording system.
 * @param sending_system  Pointer to NetFlow sending system.
 * @param options         Pointer to pointer options storage.
 * @return                Status of function processing.
 */
uint8_t flow_epilogue (netflow_recording_system_t netflow_records,
                       netflow_sending_system_t sending_system,
                       options_t options);

/*
 * Function to running the main algorithm of the NetFlow exporter.
 *
 * @param netflow_records Pointer to NetFlow recording system.
 * @param sending_system  Pointer to NetFlow sending system.
 * @param options         Pointer to pointer options storage.
 */
uint8_t run_exporter (netflow_recording_system_t netflow_records,
                      netflow_sending_system_t sending_system,
                      options_t options);

/*
 * Main function of Netflow exporter.
 */
int main (int argc, char* argv[]);

#endif // FLOW_H
