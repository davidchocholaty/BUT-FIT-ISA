/**********************************************************/
/*                                                        */
/* File: memory.h                                         */
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
 * The function figures out if the pointer points
 * to the allocated memory or not.
 *
 * @param ptr The pointer to the allocated memory.
 * @return    True if the pointer points to the allocated memory
 *            or false if its value is NULL.
 */
bool is_allocated (void* ptr);

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
 * @param string            Pointer to pointer to string.
 * @param characters_number The number of characters in a string.
 * @return                  Status of function processing.
 */
uint8_t allocate_string (char** string, size_t characters_number);

/*
 * Function for allocating the socket.
 *
 * @param socket Pointer to pointer to the storage of the socket value.
 * @return       Status of function processing.
 */
uint8_t allocate_socket (int** socket);

/*
 * Function for allocating the whole program recording system.
 *
 * @param netflow_records Pointer to pointer to the storage of the system.
 * @return                Status of function processing.
 */
uint8_t allocate_recording_system (netflow_recording_system_t* netflow_records);

/*
 * Function for allocating the whole program sending system.
 *
 * @param netflow_records Pointer to pointer to the storage of the system.
 * @return                Status of function processing.
 */
uint8_t allocate_sending_system (netflow_sending_system_t* sending_system);

/*
 * Function for allocating the flow key whose value is stored in a node
 * in a tree.
 *
 * @param flow_key Pointer to pointer to the storage of flow key.
 * @return         Status of function processing.
 */
uint8_t allocate_netflow_key (netflow_v5_key_t* flow_key);

/*
 * Function for allocating the flow record whose value is stored in a node
 * in a tree.
 *
 * @param flow_record Pointer to pointer to the storage of flow record.
 * @return            Status of function processing.
 */
uint8_t allocate_flow_node (flow_node_t* flow_record);

/*
 * Function for allocating the tree node.
 *
 * @param tree Pointer to pointer to the storage of a tree node.
 * @return     Status of function processing.
 */
uint8_t allocate_tree_node (bst_node_t* tree);

/*
 * Function for freeing memory which was allocated for the options structure
 * and the substructures.
 *
 * @param options Pointer to pointer to options storage.
 */
void free_options_mem (options_t* options);

/*
 * Function for freeing memory which was allocated for the netflow key.
 *
 * @param flow_key Pointer to pointer to the storage of netflow key.
 */
void free_netflow_key (netflow_v5_key_t* flow_key);

/*
 * Function for freeing memory which was allocated for the flow node value.
 *
 * @param flow_record Pointer to pointer to the storage of flow record.
 */
void free_flow_node (flow_node_t* flow_record);

/*
 * Function for freeing memory which was allocated for the tree node.
 *
 * @param flow_record Pointer to pointer to the storage of tree node.
 */
void free_tree_node (bst_node_t* tree_node);

/*
 * Function for freeing memory which was allocated for the tree node.
 * The difference is that this function does not free the allocated memory
 * for the key and flow value stored in the tree node.
 *
 * @param flow_record Pointer to pointer to the storage of tree node.
 */
void free_tree_node_keep_data (bst_node_t* tree_node);

/*
 * Function for freeing memory for flow node values which were stored
 * in an array.
 *
 * @param flows        An array containing flow node values.
 * @param flows_number The number of flow node values in the array.
 */
void free_flow_values_array (flow_node_t* flows, uint16_t flows_number);

/*
 * Function for freeing memory which was allocated for the string.
 *
 * @param string Pointer to pointer to the storage of string.
 */
void free_string (char** string);

/*
 * Function for freeing memory which was allocated for the socket.
 *
 * @param string Pointer to pointer to the storage of socket.
 */
void free_socket (int** socket);

/*
 * Function for freeing memory which was allocated for the netflow
 * recording system.
 *
 * @param netflow_records Pointer to pointer to the storage
 *                        of the netflow recording system.
 */
void free_recording_system (netflow_recording_system_t* netflow_records);

/*
 * Function for freeing memory which was allocated for the sending system.
 *
 * @param sending_system  Pointer to pointer to the storage
 *                        of the sending system.
 */
void free_sending_system (netflow_sending_system_t* sending_system);

/*
 * Function for freeing the whole allocated memory in the program at the end
 * of the program.
 *
 * @param options         Pointer to pointer to options storage.
 * @param netflow_records Pointer to pointer to the storage
 *                        of the netflow recording system.
 * @param sending_system  Pointer to pointer to the storage
 *                        of the sending system.
 */
void free_allocated_mem (options_t* options,
                         netflow_recording_system_t* netflow_records,
                         netflow_sending_system_t* sending_system);

#endif // FLOW_MEMORY_H
