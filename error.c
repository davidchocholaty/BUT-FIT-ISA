/**********************************************************/
/*                                                        */
/* File: error.c                                          */
/* Created: 2022-10-13                                    */
/* Last change: 2022-10-13                                */
/* Author: David Chocholaty <xchoch09@stud.fit.vutbr.cz>  */
/* Project: Project for the course ISA - variant 1        */
/*          - Generation of NetFlow data from captured    */
/*            network traffic.                            */
/* Description: Errors for the NetFlow exporter           */
/*                                                        */
/**********************************************************/

#include "error.h"

#include <stdint.h>
#include <stdio.h>

#include "option.h"

/*
 * Function for printing error message
 *
 * @param error Error code.
 * @param program_name Name of program.
 */
void print_error (uint8_t error, char* program_name)
{
    const char *error_msg[] =
    {
        "exit success",
        "invalid option",
        "invalid input file",
        "multi entry of an option",
        "active timeout not in range",
        "inactive timeout not in range",
        "flow-cache size not in range",
        "closing input file error",
        "error while handling memory",
        "unknown error"
    };

    if (error > UNKNOWN_ERROR)
    {
        error = UNKNOWN_ERROR;
    }

    fprintf(stderr, "Error: %s\n", error_msg[error]);

    if (error == INVALID_OPTION_ERROR ||
        error == ACTIVE_RANGE_ERROR ||
        error == INACTIVE_RANGE_ERROR)
    {
        print_help(program_name);
    }
}
