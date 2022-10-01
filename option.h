/**********************************************************/
/*                                                        */
/* File: option.h                                         */
/* Created: 2022-09-30                                    */
/* Last change: 2022-10-01                                */
/* Author: David Chocholaty <xchoch09@stud.fit.vutbr.cz>  */
/* Project: Project for the course ISA - variant 1        */
/*          - Generation of NetFlow data from captured    */
/*            network traffic.                            */
/* Description: Header file for options handler           */
/*                                                        */
/**********************************************************/

#ifndef OPTION_H
#define OPTION_H

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>

typedef struct analyzed_input *analyzed_input_t;
typedef struct netflow_collector *netflow_collector_t;
typedef struct active_timeout *active_timeout_t;
typedef struct inactive_timeout *inactive_timeout_t;
typedef struct cached_entries *cached_entries_t;
typedef struct options *options_t;

// The ranges values for timeouts are taken from the source on 2022-10-01:
// https://www.cisco.com/en/US/docs/ios/12_3t/netflow/command/reference/nfl_a1gt_ps5207_TSD_Products_Command_Reference_Chapter.html

enum active_timeout_range
{
    ACTIVE_TIMEOUT_MIN = 60,
    ACTIVE_TIMEOUT_MAX = 3600
};

enum inactive_timeout_range
{
    INACTIVE_TIMEOUT_MIN = 10,
    INACTIVE_TIMEOUT_MAX = 600
};

enum entries_number_range
{
    ENTRIES_NUMBER_MIN = 1024,
    ENTRIES_NUMBER_MAX = 524288
};

struct analyzed_input
{
    bool is_user_set;
    FILE* source;
} analyzed_input_default = {false, NULL};

struct netflow_collector
{
    bool is_user_set;
    char* source; // TODO somewhere malloc
} netflow_collector_default = {false, NULL};

struct active_timeout
{
    bool is_user_set;
    uint16_t timeout_seconds;
} active_timeout_default = {false, ACTIVE_TIMEOUT_MIN};

struct inactive_timeout
{
    bool is_user_set;
    uint16_t timeout_seconds;
} inactive_timeout_default = {false, INACTIVE_TIMEOUT_MIN};

struct cached_entries
{
    bool is_user_set;
    uint32_t entries_number;
} cached_entries_default = {false, ENTRIES_NUMBER_MIN};

struct options
{
    analyzed_input_t analyzed_input_source;
    netflow_collector_t netflow_collector_source;
    // 60 - 3600 seconds (project default: 60, documentation default: 1800)
    active_timeout_t active_entries_timeout;
    // 10 - 600 seconds (project default: 10, documentation default: 15)
    inactive_timeout_t inactive_entries_timeout;
    // 1024 - 524288 (project default: 1024, documentation default: 4096)
    cached_entries_t cached_entries_number;
} options_default = {&analyzed_input_default,
                     &netflow_collector_default,
                     &active_timeout_default,
                     &inactive_timeout_default,
                     &cached_entries_default};

/*
 * Function for print help
 *
 * @param program_name Name of program.
 */
void print_help (char* program_name);

/*
 * Main function for parsing arguments
 *
 * @param argc Count of arguments.
 * @param argv Arguments.
 * @param opt  Pointer to options storage.
 * @return     Status of function processing.
 */
int parse_options (int argc, char* argv[], options_t opt);

#endif // OPTION_H
