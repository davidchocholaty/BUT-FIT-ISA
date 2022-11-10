/**********************************************************/
/*                                                        */
/* File: error.h                                          */
/* Created: 2022-10-13                                    */
/* Last change: 2022-10-13                                */
/* Author: David Chocholaty <xchoch09@stud.fit.vutbr.cz>  */
/* Project: Project for the course ISA - variant 1        */
/*          - Generation of NetFlow data from captured    */
/*            network traffic.                            */
/* Description: Header file for errors                    */
/*                                                        */
/**********************************************************/

#ifndef FLOW_ERROR_H
#define FLOW_ERROR_H

#include <stdint.h>

enum error
{
    NO_ERROR,
    INVALID_OPTION_ERROR,
    INVALID_INPUT_FILE_ERROR,
    MULTIPLE_OPTION_ERROR,
    ACTIVE_RANGE_ERROR,
    INACTIVE_RANGE_ERROR,
    ENTRIES_NUMBER_ERROR,
    CLOSING_INPUT_FILE_ERROR,
    MEMORY_HANDLING_ERROR,
    SOCKET_ERROR,
    PACKET_SENDING_ERROR,
    UNKNOWN_ERROR
};

/*
 * Function for printing error message
 *
 * @param error Error code.
 * @param program_name Name of program.
 */
void print_error (uint8_t error, char* program_name);

#endif // FLOW_ERROR_H
