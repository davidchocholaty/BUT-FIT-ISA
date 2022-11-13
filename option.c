/**********************************************************/
/*                                                        */
/* File: option.c                                         */
/* Created: 2022-09-30                                    */
/* Last change: 2022-10-26                                */
/* Author: David Chocholaty <xchoch09@stud.fit.vutbr.cz>  */
/* Project: Project for the course ISA - variant 1        */
/*          - Generation of NetFlow data from captured    */
/*            network traffic.                            */
/* Description: Options handler for the NetFlow exporter  */
/*                                                        */
/**********************************************************/

#include "option.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "error.h"
#include "memory.h"
#include "util.h"

#define SET   true
#define UNSET false

/*
 * The function initialized options structure and the substructures.
 * That means that the memory is allocated and the default values are set.
 *
 * @param options Pointer to pointer to options storage.
 * @return        Status of function processing.
 */
uint8_t init_options (options_t* options)
{
    uint8_t status = allocate_options(options);

    if (status != EXIT_SUCCESS)
    {
        return MEMORY_HANDLING_ERROR;
    }

    // Set default values of the variables of the structures.
    (*options)->help_set = UNSET;

    (*options)->analyzed_input_source->is_user_set = UNSET;
    (*options)->analyzed_input_source->file_name = NULL;

    (*options)->netflow_collector_source->is_user_set = UNSET;
    (*options)->netflow_collector_source->source = NULL;

    (*options)->active_entries_timeout->is_user_set = UNSET;
    (*options)->active_entries_timeout->timeout_seconds = ACTIVE_TIMEOUT_MIN;

    (*options)->inactive_entries_timeout->is_user_set = UNSET;
    (*options)->inactive_entries_timeout->timeout_seconds = INACTIVE_TIMEOUT_MIN;

    (*options)->cached_entries_number->is_user_set = UNSET;
    (*options)->cached_entries_number->entries_number = ENTRIES_NUMBER_MIN;

    return NO_ERROR;
}

/*
 * Function for print help
 *
 * @param program_name Name of program.
 */
void print_help (char* program_name)
{
    printf("TODO help message %s\n", program_name);
}

/*
 * Set default value for the netflow collector source if it is not specified
 * by user.
 *
 * @param options  Pointer to options storage.
 * @return         Status of function processing.
 */
uint8_t set_default_if_not_user_set (options_t options)
{
    uint8_t status;
    static const char* default_collector_source = "127.0.0.1:2055";

    // If the netflow collector was not entered the source 127.0.0.1:2055 is set
    // as a netflow collector source.
    if (!options->netflow_collector_source->is_user_set)
    {
        status = allocate_string(&(options->netflow_collector_source->source),
                                 strlen(default_collector_source));

        if (status != EXIT_SUCCESS)
        {
            return MEMORY_HANDLING_ERROR;
        }

        strcpy(options->netflow_collector_source->source, default_collector_source);
    }

    return EXIT_SUCCESS;
}

/*
 * Main function for parsing arguments
 *
 * @param argc    Count of arguments.
 * @param argv    Arguments.
 * @param options  Pointer to options storage.
 * @return        Status of function processing.
 */
uint8_t parse_options (int argc, char* argv[], options_t options)
{
    uint8_t status;
    int input_option;

    // Colon as the first character disables getopt to print errors.
    while ((input_option = getopt(argc, argv, ":hf:c:a:i:m:")) != -1)
    {
        switch (input_option) {
            case 'h':
                options->help_set = true;

                break;
            case 'f':
                // The second occurrence of the parameter.
                if (options->analyzed_input_source->is_user_set)
                {
                    return MULTIPLE_OPTION_ERROR;
                }

                options->analyzed_input_source->is_user_set = SET;

                status = allocate_string(&(options->analyzed_input_source->file_name),
                                         strlen(optarg));

                if (status != EXIT_SUCCESS)
                {
                    return MEMORY_HANDLING_ERROR;
                }

                strcpy(options->analyzed_input_source->file_name, optarg);

                break;
            case 'c':
                // The second occurrence of the parameter.
                if (options->netflow_collector_source->is_user_set)
                {
                    return MULTIPLE_OPTION_ERROR;
                }

                options->netflow_collector_source->is_user_set = SET;

                status = allocate_string(&(options->netflow_collector_source->source),
                                         strlen(optarg));

                if (status != EXIT_SUCCESS)
                {
                    return MEMORY_HANDLING_ERROR;
                }

                strcpy(options->netflow_collector_source->source, optarg);

                // TODO done check on NULL and if the structure is valid later
                //  for get hostbyname - what it does if the parameter is NULL

                break;
            case 'a':
                // The second occurrence of the parameter.
                if (options->active_entries_timeout->is_user_set)
                {
                    return MULTIPLE_OPTION_ERROR;
                }

                options->active_entries_timeout->is_user_set = SET;

                if (optarg[0] != '-')
                {
                    options->active_entries_timeout->timeout_seconds = strtoui_16(optarg);

                    // Check if the value is in the allowed range. At the same time,
                    // it is checked if the input value was possible to convert
                    // to an unsigned int data type.
                    if (!in_range((unsigned int)options->active_entries_timeout->timeout_seconds,
                                  ACTIVE_TIMEOUT_MIN, ACTIVE_TIMEOUT_MAX))
                    {
                        printf("returning error\n");
                        return ACTIVE_RANGE_ERROR;
                    }
                }
                else
                {
                    return INVALID_OPTION_ERROR;
                }

                break;
            case 'i':
                // The second occurrence of the parameter.
                if (options->inactive_entries_timeout->is_user_set)
                {
                    return MULTIPLE_OPTION_ERROR;
                }

                options->inactive_entries_timeout->is_user_set = SET;

                if (optarg[0] != '-')
                {
                    options->inactive_entries_timeout->timeout_seconds = strtoui_16(optarg);

                    // Check if the value is in the allowed range. At the same time,
                    // it is checked if the input value was possible to convert
                    // to an unsigned int data type.
                    if (!in_range((unsigned int)options->inactive_entries_timeout->timeout_seconds,
                                  INACTIVE_TIMEOUT_MIN, INACTIVE_TIMEOUT_MAX))
                    {
                        return INACTIVE_RANGE_ERROR;
                    }
                }
                else
                {
                    return INVALID_OPTION_ERROR;
                }

                break;
            case 'm':
                // The second occurrence of the parameter.
                if (options->cached_entries_number->is_user_set)
                {
                    return MULTIPLE_OPTION_ERROR;
                }

                options->cached_entries_number->is_user_set = SET;

                if (optarg[0] != '-')
                {
                    options->cached_entries_number->entries_number = strtoui_32(optarg);

                    // Check if the value is in the allowed range. At the same time,
                    // it is checked if the input value was possible to convert
                    // to an unsigned int data type.
                    if (!in_range((unsigned int)options->cached_entries_number->entries_number,
                                  ENTRIES_NUMBER_MIN, ENTRIES_NUMBER_MAX))
                    {
                        return ENTRIES_NUMBER_ERROR;
                    }
                }
                else
                {
                    return INVALID_OPTION_ERROR;
                }

                break;
            case ':':
            case '?':
                return INVALID_OPTION_ERROR;
            default:
                break;
        }
    }

    return set_default_if_not_user_set(options);
}

/*
 * Function for handling the options for the Netflow exporter. The function
 * handles options initialization, options parsing and eventually
 * the help message printing.
 *
 * @param argc     Count of arguments.
 * @param argv     Arguments.
 * @param options  Pointer to pointer options storage.
 * @return         Status of function processing.
 */
uint8_t handle_options (int argc, char* argv[], options_t* options)
{
    uint8_t status;

    // Initialize options
    status = init_options(options);

    if (status != NO_ERROR)
    {
        print_error(status, argv[0]);

        return status;
    }

    // Parse options
    status = parse_options(argc, argv, *options);

    if (status != NO_ERROR)
    {
        print_error(status, argv[0]);

        free_options_mem(options);

        return status;
    }

    // Help printing
    if ((*options)->help_set)
    {
        print_help(argv[0]);
    }

    return NO_ERROR;
}
