/**********************************************************/
/*                                                        */
/* File: flow.c                                           */
/* Created: 2022-09-30                                    */
/* Last change: 2022-10-26                                */
/* Author: David Chocholaty <xchoch09@stud.fit.vutbr.cz>  */
/* Project: Project for the course ISA - variant 1        */
/*          - Generation of NetFlow data from captured    */
/*            network traffic.                            */
/* Description: NetFlow exporter                          */
/*                                                        */
/**********************************************************/

#include "flow.h"

#include <stdlib.h>

#include "error.h"
#include "memory.h"
#include "option.h"
#include "pcap.h"

/*
 * Function to handle needed operations before ending of flow program.
 * The needed operations is:
 * - free options allocated memory
 *
 * @param options      Pointer to pointer options storage.
 * @return             Status of function processing.
 */
uint8_t flow_epilogue (options_t* options)
{
    // Free options allocated memory.
    free_options_mem(options);

    return NO_ERROR;
}

/*
 * Main function of Netflow exporter.
 */
int main (int argc, char* argv[])
{
    options_t options = NULL;
    uint8_t status = handle_options(argc, argv, &options);

    if (status != NO_ERROR)
    {
        return EXIT_FAILURE;
    }

    // TODO handling pcap
    handle_pcap(options->analyzed_input_source->file_name);

    status = flow_epilogue(&options);

    if (status != NO_ERROR)
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
