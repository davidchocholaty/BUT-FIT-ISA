/**********************************************************/
/*                                                        */
/* File: option.c                                         */
/* Created: 2022-09-30                                    */
/* Last change: 2022-10-01                                */
/* Author: David Chocholaty <xchoch09@stud.fit.vutbr.cz>  */
/* Project: Project for the course ISA - variant 1        */
/*          - Generation of NetFlow data from captured    */
/*            network traffic.                            */
/* Description: Options handler for the NetFlow exporter  */
/*                                                        */
/**********************************************************/

#include "option.h"

#include <stdio.h>
#include <unistd.h>

#include "util.h"

#define SET   true
#define UNSET false

/*
 * Function for print help
 *
 * @param program_name Name of program.
 */
void print_help (char* program_name)
{
    printf("TODO");
}

/*
 * Main function for parsing arguments
 *
 * @param argc Count of arguments.
 * @param argv Arguments.
 * @param opt  Pointer to options storage.
 * @return     Status of function processing.
 */
int parse_options (int argc, char* argv[], options_t option)
{
    int input_option;

    // Colon as the first character disables getopt to print errors.
    while ((input_option = getopt(argc, argv, ":f:c:a:i:m:")) != -1)
    {
        switch (input_option) {
            case 'f':
                if (option->analyzed_input_source->is_user_set)
                {
                    // TODO error
                }

                option->analyzed_input_source->source = fopen(optarg, "r");

                if (option->analyzed_input_source->source == NULL) {
                    // TODO error
                }

                break;
            case 'c':
                if (option->netflow_collector_source->is_user_set)
                {
                    // TODO error
                }

                option->netflow_collector_source->is_user_set = SET;

                // TODO check on NULL and if the structure is valid

                break;
            case 'a':
                if (option->active_entries_timeout->is_user_set)
                {
                    // TODO error
                }

                option->active_entries_timeout->is_user_set = SET;

                if (optarg[0] != '-')
                {
                    option->active_entries_timeout->timeout_seconds = strtoui_16(optarg);

                    // Check if the value is in the allowed range. At the same time,
                    // it is checked if the input value was possible to convert
                    // to an unsigned int data type.
                    if (!in_range(option->active_entries_timeout->timeout_seconds,
                                  ACTIVE_TIMEOUT_MIN, ACTIVE_TIMEOUT_MAX))
                    {
                        // TODO error
                    }
                }
                else
                {
                    // TODO error
                }

                break;
            case 'i':
                if (option->inactive_entries_timeout->is_user_set)
                {
                    // TODO error
                }

                option->inactive_entries_timeout->is_user_set = SET;

                if (optarg[0] != '-')
                {
                    option->inactive_entries_timeout->timeout_seconds = strtoui_16(optarg);

                    // Check if the value is in the allowed range. At the same time,
                    // it is checked if the input value was possible to convert
                    // to an unsigned int data type.
                    if (!in_range(option->inactive_entries_timeout->timeout_seconds,
                                  INACTIVE_TIMEOUT_MIN, INACTIVE_TIMEOUT_MAX))
                    {
                        // TODO error
                    }
                }
                else
                {
                    // TODO error
                }

                break;
            case 'm':
                if (option->cached_entries_number->is_user_set)
                {
                    // TODO error
                }

                option->cached_entries_number->is_user_set = SET;

                if (optarg[0] != '-')
                {
                    option->cached_entries_number->entries_number = strtoui_32(optarg);

                    // Check if the value is in the allowed range. At the same time,
                    // it is checked if the input value was possible to convert
                    // to an unsigned int data type.
                    if (!in_range(option->cached_entries_number->entries_number,
                                  ENTRIES_NUMBER_MIN, ENTRIES_NUMBER_MAX))
                    {
                        // TODO error
                    }
                }
                else
                {
                    // TODO error
                }

                break;
            default:
                // TODO
                break;
        }
    }

    // TODO move the setting of default value of the analyzed input source
    //  and netflow collector source to another function.

    // If the name of the analyzed file was not entered the input will be read
    // from the stdin.
    if (!option->analyzed_input_source->is_user_set)
    {
        option->analyzed_input_source->source = stdin;
    }

    // If the netflow collector was not entered the source 127.0.0.1:2055 is set
    // as a netflow collector source.
    if (!option->netflow_collector_source->is_user_set)
    {
        option->netflow_collector_source->source = "127.0.0.1:2055";
    }
}
