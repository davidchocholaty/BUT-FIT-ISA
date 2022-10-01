/**********************************************************/
/*                                                        */
/* File: util.h                                           */
/* Created: 2022-10-01                                    */
/* Last change: 2022-10-01                                */
/* Author: David Chocholaty <xchoch09@stud.fit.vutbr.cz>  */
/* Project: Project for the course ISA - variant 1        */
/*          - Generation of NetFlow data from captured    */
/*            network traffic.                            */
/* Description: Header file for util                      */
/*                                                        */
/**********************************************************/

#ifndef UTIL_H
#define UTIL_H

/*
 * TODO
 */
bool is_numeric_string(char* string);

/*
 * Function for convert string to uint16_t.
 *
 * @param string Input string
 * @return       If string doesn't contain uint16_t number: 0L,
 *               number in uint16_t data type otherwise.
 */
uint16_t strtoui_16 (char* string);

/*
 * Function for convert string to uint32_t.
 *
 * @param string Input string
 * @return       If string doesn't contain uint32_t number: 0L,
 *               number in uint32_t data type otherwise.
 */
uint16_t strtoui_32 (char* string);

/*
 * TODO
 */
bool in_range (const unsigned int value,
               const unsigned int min,
               const unsigned int max);

#endif // UTIL_H
