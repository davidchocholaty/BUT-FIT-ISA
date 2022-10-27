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

#endif // FLOW_MEMORY_H
