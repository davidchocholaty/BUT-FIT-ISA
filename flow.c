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
#include <string.h>
#include <unistd.h>

#include <netdb.h> // For Merlin server.

#include "error.h"
#include "memory.h"
#include "netflow_v5.h"
#include "option.h"
#include "pcap.h"
#include "util.h"

#define DEFAULT_PORT 2055

uint8_t connect_socket (int* sock, char* source)
{
    struct sockaddr_in server;//, from; // address structures of the server and the client
    struct hostent *servent;         // network host entry required by gethostbyname()

    uint8_t status = NO_ERROR;
    char* source_name = NULL;
    char* source_port = NULL;

    uint16_t port_numeric;

    status = parse_name_port(source, &source_name, &source_port);

    printf("name: %s\n", source_name);

    if (status != NO_ERROR)
    {
        return status;
    }

    memset(&server, 0, sizeof(server)); // erase the server structure
    server.sin_family = AF_INET;

    // make DNS resolution of the first parameter using gethostbyname()

    // check the first parameter
    if ((servent = gethostbyname(source_name)) == NULL)
    {
        free_string(&source_name);
        free_string(&source_port);

        return SOCKET_ERROR;
    }

    // copy the first parameter to the server.sin_addr structure
    memcpy(&server.sin_addr, servent->h_addr, servent->h_length);

    if (source_port != NULL)
    {
        port_numeric = strtoui_16(source_port);

        if (port_numeric == 0)
        {
            return INVALID_OPTION_ERROR;
        }

        server.sin_port = htons(port_numeric);        // server port (network byte order)

        printf("port: %hu\n", port_numeric);
    }
    else
    {
        server.sin_port = htons(DEFAULT_PORT);

        printf("port: %d\n", DEFAULT_PORT);
    }

    //create a client socket
    if ((*sock = socket(AF_INET , SOCK_DGRAM , 0)) == -1)
    {
        return SOCKET_ERROR;
    }

    //len = sizeof(server);
    //fromlen = sizeof(from);

    // create a connected UDP socket
    if (connect(*sock, (struct sockaddr *)&server, sizeof(server))  == -1)
    {
        return SOCKET_ERROR;
    }

    free_string(&source_name);
    free_string(&source_port);

    return NO_ERROR;
}

void disconnect_socket (const int* sock)
{
    close(*sock);
}

/*
 * Function to handle needed operations before ending of flow program.
 * The needed operations is:
 * - free options allocated memory
 *
 * @param options         Pointer to pointer options storage.
 * @param netflow_records Pointer to NetFlow recording system.
 * @return                Status of function processing.
 */
uint8_t flow_epilogue (options_t options,
                       netflow_recording_system_t netflow_records,
                       netflow_sending_system_t sending_system)
{
    uint8_t status;

    status = export_all_flows_dispose_tree(netflow_records, sending_system);

    if (sending_system != NULL && sending_system->socket)
    {
        disconnect_socket(sending_system->socket);
    }

    free_allocated_mem(&options, &netflow_records, &sending_system);

    return status;
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
