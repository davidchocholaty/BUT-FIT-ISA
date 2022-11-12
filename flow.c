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
#include "netflow_v5.h"
#include "option.h"
#include "pcap.h"

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
                       netflow_recording_system_t netflow_records,
                       netflow_sending_system_t sending_system)
{
    export_all_flows_dispose_tree(netflow_records, sending_system);

    if (sending_system != NULL && sending_system->socket)
    {
        disconnect_socket(sending_system->socket);
    }

    free_allocated_mem(&options, &netflow_records, &sending_system);

    return NO_ERROR;
}

uint8_t run_exporter (options_t options,
                      netflow_recording_system_t netflow_records,
                      netflow_sending_system_t sending_system)
{
    bst_init(&(netflow_records->tree));
    *(netflow_records->cached_flows_number) = 0;

    return run_packets_processing(netflow_records, sending_system, options);
}

/*
 * Main function of Netflow exporter.
 */
int main (int argc, char* argv[])
{
    options_t options = NULL;
    netflow_recording_system_t netflow_records = NULL;
    netflow_sending_system_t sending_system = NULL;
    uint8_t status = handle_options(argc, argv, &options);

    if (status != NO_ERROR)
    {
        return EXIT_FAILURE;
    }

    status = allocate_recording_system(&netflow_records);

    if (status != NO_ERROR)
    {
        print_error(MEMORY_HANDLING_ERROR, argv[0]);
        flow_epilogue(options, netflow_records, sending_system);

        return EXIT_FAILURE;
    }

    status = allocate_sending_system(&sending_system);

    if (status != NO_ERROR)
    {
        print_error(MEMORY_HANDLING_ERROR, argv[0]);
        flow_epilogue(options, netflow_records, sending_system);

        return EXIT_FAILURE;
    }

    status = connect_socket(sending_system->socket, options->netflow_collector_source->source);

    if (status != NO_ERROR)
    {
        print_error(status, argv[0]);
        flow_epilogue(options, netflow_records, sending_system);

        return EXIT_FAILURE;
    }

    status = run_exporter(options, netflow_records, sending_system);

    if (status != NO_ERROR)
    {
        print_error(status, argv[0]);
        flow_epilogue(options, netflow_records, sending_system);

        return EXIT_FAILURE;
    }

    status = flow_epilogue(options, netflow_records, sending_system);

    if (status != NO_ERROR)
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
