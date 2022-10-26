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

/*
 * Function to handle needed operations before ending of flow program.
 * The needed operations are:
 * - close input file
 * - free options allocated memory
 *
 * @param options Pointer to pointer options storage.
 * @param argv    Arguments.
 * @return        Status of function processing.
 */
uint8_t flow_epilogue (options_t* options, char* argv[])
{
    // TODO later when handling with file
    argv = argv;
    /*
    // Close input file if possible.
    if (options->analyzed_input_source->source == NULL)
    {
        print_error(CLOSING_INPUT_FILE_ERROR, argv[0]);

        return CLOSING_INPUT_FILE_ERROR;
    }

    fclose(options->analyzed_input_source->source);
    */

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

    status = flow_epilogue(&options, argv);

    if (status != NO_ERROR)
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
