/**********************************************************/
/*                                                        */
/* File: util.h                                           */
/* Created: 2022-10-01                                    */
/* Last change: 2022-10-13                                */
/* Author: David Chocholaty <xchoch09@stud.fit.vutbr.cz>  */
/* Project: Project for the course ISA - variant 1        */
/*          - Generation of NetFlow data from captured    */
/*            network traffic.                            */
/* Description: Header file for util                      */
/*                                                        */
/**********************************************************/

#ifndef FLOW_UTIL_H
#define FLOW_UTIL_H

/*
 * Function to check if the input string is only from numeric characters.
 *
 * @param string Input string for check.
 */
bool is_numeric_string (char* string);

/*
 * Function for convert string to uint16_t.
 *
 * @param string Input string.
 * @return       If string doesn't contain uint16_t number: 0L,
 *               number in uint16_t data type otherwise.
 */
uint16_t strtoui_16 (char* string);

/*
 * Function for convert string to uint32_t.
 *
 * @param string Input string.
 * @return       If string doesn't contain uint32_t number: 0L,
 *               number in uint32_t data type otherwise.
 */
uint32_t strtoui_32 (char* string);

/*
 * Function checks if the value is in a range between the minimum
 * and maximum value including both range sides.
 *
 * @param value Input value for check in range.
 * @param min   Minimum range value.
 * @param max   Maximum range value.
 */
bool in_range (const unsigned int value,
               const unsigned int min,
               const unsigned int max);

uint8_t parse_name_port (char* in_source, char** out_name, char** out_port);

#endif // FLOW_UTIL_H
