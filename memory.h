/**********************************************************/
/*                                                        */
/* File: memory.h                                         */
/* Created: 2022-10-26                                    */
/* Last change: 2022-10-26                                */
/* Author: David Chocholaty <xchoch09@stud.fit.vutbr.cz>  */
/* Project: Project for the course ISA - variant 1        */
/*          - Generation of NetFlow data from captured    */
/*            network traffic.                            */
/* Description: Header file for the memory handling       */
/*                                                        */
/**********************************************************/

#ifndef FLOW_MEMORY_H
#define FLOW_MEMORY_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "option.h"
#include "netflow_v5.h"

/*
 * Function for allocating memory for the options structure and the substructures.
 *
 * @param options Pointer to pointer to options storage.
 * @return        Status of function processing.
 */
uint8_t allocate_options (options_t* options);

/*
 * Function for allocating memory the string.
 *
 * @param string Pointer to pointer to string.
 * @return       Status of function processing.
 */
uint8_t allocate_string (char** string, size_t characters_number);

uint8_t allocate_socket (int** socket);

/*
 * Function for freeing memory which was allocated for the options structure
 * and the substructures.
 *
 * @param options Pointer to pointer to options storage.
 */
void free_options_mem (options_t* options);

/*
 * The function figures out if the pointer points
 * to the allocated memory or not.
 *
 * @param ptr The pointer to the allocated memory.
 * @return    True if the pointer points to the allocated memory
 *            or false if its value is NULL.
 */
bool is_allocated (void* ptr);

uint8_t allocate_recording_system (netflow_recording_system_t* netflow_records);
uint8_t allocate_sending_system (netflow_sending_system_t* sending_system);
uint8_t allocate_netflow_record (netflow_v5_flow_record_t* flow_record);
uint8_t allocate_netflow_key (netflow_v5_key_t* flow_key);
uint8_t allocate_tree_node (bst_node_t* tree);
void free_allocated_mem (options_t* options,
                         netflow_recording_system_t* netflow_records,
                         netflow_sending_system_t* sending_system);
void free_recording_system (netflow_recording_system_t* netflow_records);
void free_sending_system (netflow_sending_system_t* sending_system);
void free_netflow_record (netflow_v5_flow_record_t* flow_record);

void free_netflow_key (netflow_v5_key_t* flow_key);
void free_tree_node (bst_node_t* tree_node);
void free_tree_node_keep_data (bst_node_t* tree_node);

void free_string (char** string);

void free_socket (int** socket);

#endif // FLOW_MEMORY_H
