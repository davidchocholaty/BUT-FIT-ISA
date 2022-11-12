/**********************************************************/
/*                                                        */
/* File: option.h                                         */
/* Created: 2022-09-30                                    */
/* Last change: 2022-10-13                                */
/* Author: David Chocholaty <xchoch09@stud.fit.vutbr.cz>  */
/* Project: Project for the course ISA - variant 1        */
/*          - Generation of NetFlow data from captured    */
/*            network traffic.                            */
/* Description: Header file for options handler           */
/*                                                        */
/**********************************************************/

#ifndef FLOW_OPTION_H
#define FLOW_OPTION_H

#include <stdbool.h>
#include <stdint.h>

typedef struct analyzed_input* analyzed_input_t;
typedef struct netflow_collector* netflow_collector_t;
typedef struct active_timeout* active_timeout_t;
typedef struct inactive_timeout* inactive_timeout_t;
typedef struct cached_entries* cached_entries_t;
typedef struct options* options_t;

// The ranges values for timeouts are taken from the source on 2022-10-01:
// https://www.cisco.com/en/US/docs/ios/12_3t/netflow/command/reference/nfl_a1gt_ps5207_TSD_Products_Command_Reference_Chapter.html

enum active_timeout_range
{
    // TODO vratit zpet
    //ACTIVE_TIMEOUT_MIN = 60,
    //ACTIVE_TIMEOUT_MAX = 3600
    ACTIVE_TIMEOUT_MIN = 1,
    ACTIVE_TIMEOUT_MAX = 100
};

enum inactive_timeout_range
{
    // TODO vratit zpet
    //INACTIVE_TIMEOUT_MIN = 10,
    //INACTIVE_TIMEOUT_MAX = 600
    INACTIVE_TIMEOUT_MIN = 1,
    INACTIVE_TIMEOUT_MAX = 100
};

enum entries_number_range
{
    // TODO vratit zpet
    //ENTRIES_NUMBER_MIN = 1024,
    //ENTRIES_NUMBER_MAX = 524288
    ENTRIES_NUMBER_MIN = 1,
    ENTRIES_NUMBER_MAX = 524288
};

struct analyzed_input
{
    bool is_user_set;
    char* file_name;
};

struct netflow_collector
{
    bool is_user_set;
    char* source;
};

struct active_timeout
{
    bool is_user_set;
    uint16_t timeout_seconds;
};

struct inactive_timeout
{
    bool is_user_set;
    uint16_t timeout_seconds;
};

struct cached_entries
{
    bool is_user_set;
    uint32_t entries_number;
};

struct options
{
    bool help_set;
    analyzed_input_t analyzed_input_source;
    netflow_collector_t netflow_collector_source;
    // 60 - 3600 seconds (project default: 60, documentation default: 1800)
    active_timeout_t active_entries_timeout;
    // 10 - 600 seconds (project default: 10, documentation default: 15)
    inactive_timeout_t inactive_entries_timeout;
    // 1024 - 524288 (project default: 1024, documentation default: 4096)
    cached_entries_t cached_entries_number;
};

/*
 * The function initialized options structure and the substructures.
 * That means that the memory is allocated and the default values are set.
 *
 * @param options Pointer to pointer to options storage.
 * @return        Status of function processing.
 */
uint8_t init_options (options_t* options);

/*
 * Function for print help
 *
 * @param program_name Name of program.
 */
void print_help (char* program_name);

/*
 * Main function for parsing arguments
 *
 * @param argc    Count of arguments.
 * @param argv    Arguments.
 * @param options  Pointer to options storage.
 * @return        Status of function processing.
 */
uint8_t parse_options (int argc, char* argv[], options_t options);

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
uint8_t handle_options (int argc, char* argv[], options_t* options);

#endif // FLOW_OPTION_H
