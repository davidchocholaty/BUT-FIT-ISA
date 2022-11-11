/**********************************************************/
/*                                                        */
/* File: memory.c                                         */
/* Created: 2022-10-26                                    */
/* Last change: 2022-10-26                                */
/* Author: David Chocholaty <xchoch09@stud.fit.vutbr.cz>  */
/* Project: Project for the course ISA - variant 1        */
/*          - Generation of NetFlow data from captured    */
/*            network traffic.                            */
/* Description: Memory handling for the Netflow exporter  */
/*                                                        */
/**********************************************************/

#include "memory.h"

#include <stdbool.h>
#include <stdlib.h>

#include "option.h"
#include "netflow_v5.h"

/*
 * The function figures out if the pointer points
 * to the allocated memory or not.
 *
 * @param ptr The pointer to the allocated memory.
 * @return    True if the pointer points to the allocated memory
 *            or false if its value is NULL.
 */
bool is_allocated (void* ptr)
{
    if (ptr == NULL)
    {
        return false;
    }

    return true;
}

/*
 * Function for allocating memory for the options structure
 * and the substructures.
 *
 * @param options Pointer to pointer to options storage.
 * @return        Status of function processing.
 */
uint8_t allocate_options (options_t* options)
{
    // First, allocate memory for the options structure.
    *options = (options_t) malloc(sizeof(struct options));

    if (!is_allocated(*options))
    {
        return EXIT_FAILURE;
    }

    (*options)->analyzed_input_source =
            (analyzed_input_t) malloc(sizeof(struct analyzed_input));
    (*options)->netflow_collector_source =
            (netflow_collector_t) malloc(sizeof(struct netflow_collector));
    (*options)->active_entries_timeout =
            (active_timeout_t) malloc(sizeof(struct active_timeout));
    (*options)->inactive_entries_timeout =
            (inactive_timeout_t) malloc(sizeof(struct inactive_timeout));
    (*options)->cached_entries_number =
            (cached_entries_t) malloc(sizeof(struct cached_entries));

    if (!is_allocated((*options)->analyzed_input_source) ||
        !is_allocated((*options)->netflow_collector_source) ||
        !is_allocated((*options)->active_entries_timeout) ||
        !is_allocated((*options)->inactive_entries_timeout) ||
        !is_allocated((*options)->cached_entries_number))
    {
        free((*options)->analyzed_input_source);
        free((*options)->netflow_collector_source);
        free((*options)->active_entries_timeout);
        free((*options)->inactive_entries_timeout);
        free((*options)->cached_entries_number);

        (*options)->analyzed_input_source = NULL;
        (*options)->netflow_collector_source = NULL;
        (*options)->active_entries_timeout = NULL;
        (*options)->inactive_entries_timeout = NULL;
        (*options)->cached_entries_number = NULL;

        free(*options);
        *options = NULL;

        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

/*
 * Function for allocating memory the string.
 *
 * @param string Pointer to pointer to string.
 * @return       Status of function processing.
 */
uint8_t allocate_string (char** string, size_t characters_number)
{
    *string = (char*) malloc((characters_number + 1) * sizeof(char));

    if (!is_allocated(*string))
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

uint8_t allocate_socket (int** socket)
{
    *socket = (int*) malloc(sizeof(int));

    if (!is_allocated(*socket))
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

uint8_t allocate_recording_system (netflow_recording_system_t* netflow_records)
{
    *netflow_records =
            (netflow_recording_system_t) malloc(sizeof(struct netflow_recording_system));

    if (!is_allocated(*netflow_records))
    {
        return EXIT_FAILURE;
    }

    (*netflow_records)->tree = NULL;

    (*netflow_records)->first_packet_time =
            (struct timeval*) malloc(sizeof(struct timeval));

    if(!is_allocated((*netflow_records)->first_packet_time))
    {
        return EXIT_FAILURE;
    }

    (*netflow_records)->last_packet_time =
            (struct timeval*) malloc(sizeof(struct timeval));

    if(!is_allocated((*netflow_records)->last_packet_time))
    {
        return EXIT_FAILURE;
    }

    (*netflow_records)->cached_flows_number =
            (uint64_t*) malloc(sizeof(uint64_t));

    if (!is_allocated((*netflow_records)->cached_flows_number))
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

uint8_t allocate_sending_system (netflow_sending_system_t* sending_system)
{
    *sending_system =
            (netflow_sending_system_t) malloc(sizeof(struct netflow_sending_system));

    if (!is_allocated(*sending_system))
    {
        return EXIT_FAILURE;
    }

    if (allocate_socket(&((*sending_system)->socket)) != EXIT_SUCCESS)
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

uint8_t allocate_flow_node (flow_node_t* flow_record)
{
    *flow_record =
            (flow_node_t) malloc(sizeof(struct flow_node));

    if (!is_allocated(*flow_record))
    {
        return EXIT_FAILURE;
    }

    (*flow_record)->first =
            (struct timeval*) malloc(sizeof(struct timeval));

    if (!is_allocated((*flow_record)->first))
    {
        return EXIT_FAILURE;
    }

    (*flow_record)->last =
            (struct timeval*) malloc(sizeof(struct timeval));

    if (!is_allocated((*flow_record)->last))
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

uint8_t allocate_netflow_key (netflow_v5_key_t* flow_key)
{
    *flow_key =
            (netflow_v5_key_t) malloc(sizeof(struct netflow_v5_key));

    if (!is_allocated(flow_key))
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

uint8_t allocate_tree_node (bst_node_t* tree_node)
{
    *tree_node =
            (bst_node_t) malloc(sizeof(struct bst_node));

    if (!is_allocated(*tree_node))
    {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

void free_flow_node (flow_node_t* flow_record)
{
    if (is_allocated(*flow_record))
    {
        if (is_allocated((*flow_record)->first))
        {
            free((*flow_record)->first);
            (*flow_record)->first = NULL;
        }

        if (is_allocated((*flow_record)->last))
        {
            free((*flow_record)->last);
            (*flow_record)->last = NULL;
        }

        free(*flow_record);
        *flow_record = NULL;
    }
}

void free_netflow_key (netflow_v5_key_t* flow_key)
{
    if (is_allocated(*flow_key))
    {
        free(*flow_key);
        *flow_key = NULL;
    }
}

void free_tree_node (bst_node_t* tree_node)
{
    if (is_allocated(*tree_node))
    {
        if (is_allocated((*tree_node)->key))
        {
            free_netflow_key(&((*tree_node)->key));
        }

        if (is_allocated((*tree_node)->value))
        {
            free_flow_node(&((*tree_node)->value));
        }

        free(*tree_node);
        *tree_node = NULL;
    }
}

void free_tree_node_keep_data (bst_node_t* tree_node)
{
    if (is_allocated(*tree_node))
    {
        free(*tree_node);
        *tree_node = NULL;
    }
}

void free_string (char** string)
{
    if (is_allocated(*string))
    {
        free(*string);
        *string = NULL;
    }
}

void free_socket (int** socket)
{
    if (is_allocated(*socket))
    {
        free(*socket);
        *socket = NULL;
    }
}

/*
 * Function for freeing memory which was allocated for the options structure
 * and the substructures.
 *
 * @param options Pointer to pointer options storage.
 */
void free_options_mem (options_t* options)
{
    if (is_allocated(*options))
    {
        if (is_allocated((*options)->netflow_collector_source) &&
            is_allocated((*options)->netflow_collector_source->source))
        {
            free((*options)->netflow_collector_source->source);
            (*options)->netflow_collector_source->source = NULL;
        }

        if (is_allocated((*options)->analyzed_input_source) &&
            is_allocated((*options)->analyzed_input_source->file_name))
        {
            free((*options)->analyzed_input_source->file_name);
            (*options)->analyzed_input_source->file_name = NULL;
        }

        free((*options)->analyzed_input_source);
        free((*options)->netflow_collector_source);
        free((*options)->active_entries_timeout);
        free((*options)->inactive_entries_timeout);
        free((*options)->cached_entries_number);

        (*options)->analyzed_input_source = NULL;
        (*options)->netflow_collector_source = NULL;
        (*options)->active_entries_timeout = NULL;
        (*options)->inactive_entries_timeout = NULL;
        (*options)->cached_entries_number = NULL;

        free(*options);
        *options = NULL;
    }
}

void free_recording_system (netflow_recording_system_t* netflow_records)
{
    if (is_allocated(*netflow_records))
    {
        if (is_allocated((*netflow_records)->first_packet_time))
        {
            free((*netflow_records)->first_packet_time);
            (*netflow_records)->first_packet_time = NULL;
        }

        if (is_allocated((*netflow_records)->last_packet_time))
        {
            free((*netflow_records)->last_packet_time);
            (*netflow_records)->last_packet_time = NULL;
        }

        if (is_allocated((*netflow_records)->cached_flows_number))
        {
            free((*netflow_records)->cached_flows_number);
            (*netflow_records)->cached_flows_number = NULL;
        }

        free(*netflow_records);
        *netflow_records = NULL;
    }
}

void free_sending_system (netflow_sending_system_t* sending_system)
{
    if (is_allocated(*sending_system))
    {
        if (is_allocated((*sending_system)->socket))
        {
            free_socket(&((*sending_system)->socket));
        }

        free(*sending_system);
        *sending_system = NULL;
    }
}

void free_allocated_mem (options_t* options,
                         netflow_recording_system_t* netflow_records,
                         netflow_sending_system_t* sending_system)
{
    free_options_mem(options);
    free_recording_system(netflow_records);
    free_sending_system(sending_system);
}
