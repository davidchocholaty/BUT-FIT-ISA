/**********************************************************/
/*                                                        */
/* File: flow.c                                           */
/* Author: David Chocholaty <xchoch09@stud.fit.vutbr.cz>  */
/* Project: Project for the course ISA - variant 1        */
/*          - Generation of NetFlow data from captured    */
/*            network traffic.                            */
/* Description: NetFlow exporter                          */
/*                                                        */
/**********************************************************/

#include "flow.h"

#include <arpa/inet.h>
#include <netdb.h> // For Merlin server.
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "error.h"
#include "memory.h"
#include "netflow_v5.h"
#include "option.h"
#include "pcap.h"
#include "util.h"

#define DEFAULT_PORT 2055

/*
 * Function for connecting socket to establishing a connection
 * with a NetFlow collector.
 *
 * This function is inspired of the following source:
 *
 * Source: Course ISA at BUT FIT 2022 (https://www.fit.vut.cz/study/course/ISA/.en)
 * Lecture: 2. Advanced programming of TCP/IP network applications.
 * File: echo-udp-client2.c
 * Year of creation: 2016
 * Year of the last file modification: 2019
 * Author: Matoušek Petr, doc. Ing., Ph.D., M.A. (https://www.fit.vut.cz/person/matousp/.en)
 *
 * @param sock   Pointer to socket.
 * @param source String containing a collector name and possibly port.
 * @return       Status of function processing.
 */
uint8_t connect_socket (int* sock, char* source)
{
    uint8_t status;
    uint16_t port_numeric;
    struct sockaddr_in server; // Address structure of the server.
    struct hostent *servent;   // Network host entry required by gethostbyname().
    char* source_name = NULL;
    char* source_port = NULL;

    status = parse_name_port(source, &source_name, &source_port);

    if (status != NO_ERROR)
    {
        return status;
    }

    memset(&server, 0, sizeof(server)); // Erase the server structure.
    server.sin_family = AF_INET;

    // Make DNS resolution of the first parameter using gethostbyname().
    // Check the first parameter.
    if ((servent = gethostbyname(source_name)) == NULL)
    {
        free_string(&source_name);
        free_string(&source_port);

        return SOCKET_ERROR;
    }

    // Copy the first parameter to the server.sin_addr structure.
    memcpy(&server.sin_addr, servent->h_addr, servent->h_length);

    if (source_port != NULL)
    {
        port_numeric = strtoui_16(source_port);

        if (port_numeric == 0)
        {
            return INVALID_OPTION_ERROR;
        }

        // Server port (network byte order).
        server.sin_port = htons(port_numeric);

        // Print info about collector.
        printf("netflow_collector:port: %s:%d\n", source_name, port_numeric);
    }
    else
    {
        server.sin_port = htons(DEFAULT_PORT);

        // Print info about collector.
        printf("netflow_collector:port: %s:%d\n", source_name, DEFAULT_PORT);
    }

    // Create a client socket.
    if ((*sock = socket(AF_INET , SOCK_DGRAM , 0)) == -1)
    {
        return SOCKET_ERROR;
    }

    // Create a connected UDP socket.
    if (connect(*sock, (struct sockaddr *)&server, sizeof(server))  == -1)
    {
        return SOCKET_ERROR;
    }

    free_string(&source_name);
    free_string(&source_port);

    return NO_ERROR;
}

/*
 * Function for disconnecting the created socket.
 *
 * @param sock Pointer to socket.
 */
void disconnect_socket (const int* sock)
{
    close(*sock);
}

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
                       options_t options)
{
    uint8_t status;

    status = export_all_flows_dispose_tree(netflow_records, sending_system);

    if (sending_system != NULL && sending_system->socket)
    {
        disconnect_socket(sending_system->socket);
    }

    if (netflow_records != NULL)
    {
        printf("\n");
        printf("Exported %lu flows in %lu packets\n",
               *(netflow_records->flows_statistics),
               *(netflow_records->sent_packets_statistics));
    }

    free_allocated_mem(&options, &netflow_records, &sending_system);

    return status;
}

uint8_t run_exporter (netflow_recording_system_t netflow_records,
                      netflow_sending_system_t sending_system,
                      options_t options)
{
    bst_init(&(netflow_records->tree));
    *(netflow_records->cached_flows_number) = 0;
    *(netflow_records->flows_statistics) = 0;
    *(netflow_records->sent_packets_statistics) = 0;

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
    else if (options->help_set)
    {
        flow_epilogue(netflow_records, sending_system, options);
        return EXIT_SUCCESS;
    }

    // Print intro message.
    printf("flow v1.0.0\n");
    printf("\n");
    printf("\n");
    printf("Settings:\n");
    printf("---------\n");

    // Print info about options settings.
    printf("active_timer: %d\n", options->active_entries_timeout->timeout_seconds);
    printf("inactive_timer: %d\n", options->inactive_entries_timeout->timeout_seconds);
    printf("cache_size: %d\n", options->cached_entries_number->entries_number);

    status = allocate_recording_system(&netflow_records);

    if (status != NO_ERROR)
    {
        print_error(MEMORY_HANDLING_ERROR, argv[0]);
        flow_epilogue(netflow_records, sending_system, options);

        return EXIT_FAILURE;
    }

    status = allocate_sending_system(&sending_system);

    if (status != NO_ERROR)
    {
        print_error(MEMORY_HANDLING_ERROR, argv[0]);
        flow_epilogue(netflow_records, sending_system, options);

        return EXIT_FAILURE;
    }

    status = connect_socket(sending_system->socket,
                            options->netflow_collector_source->source);

    if (status != NO_ERROR)
    {
        print_error(status, argv[0]);
        flow_epilogue(netflow_records, sending_system, options);

        return EXIT_FAILURE;
    }

    status = run_exporter(netflow_records, sending_system, options);

    if (status != NO_ERROR)
    {
        print_error(status, argv[0]);
        flow_epilogue(netflow_records, sending_system, options);

        return EXIT_FAILURE;
    }

    status = flow_epilogue(netflow_records, sending_system, options);

    if (status != NO_ERROR)
    {
        return EXIT_FAILURE;
    }

    printf("\n");
    printf("End of processing packets ...\n");

    return EXIT_SUCCESS;
}
