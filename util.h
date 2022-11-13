/**********************************************************/
/*                                                        */
/* File: util.h                                           */
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
 * @return       True is the string contains only numeric value, false otherwise.
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
 * @return      True if the specified value is in the range between min and max,
 *              false otherwise.
 */
bool in_range (unsigned int value,
               unsigned int min,
               unsigned int max);

/*
 * Function for parsing the collector source for the name and port separately.
 *
 * @param in_source The input which contains the collector source.
 * @param out_name  The output parameter that contains the name
 *                  of the collector.
 * @param out_port  The output parameter that contains the port
 *                  of the collector.
 * @return          Status of function processing.
 */
uint8_t parse_name_port (char* in_source, char** out_name, char** out_port);

/*
 * Function for returning the numeric value of a time in milliseconds.
 *
 * @param time              Current time value.
 * @param first_packet_time Time of the first caught packet.
 * @return                  The numeric time value in milliseconds.
 */
u_int32_t get_timeval_ms(struct timeval* time, struct timeval* first_packet_time);

/*
 * Function of comparing two time values.
 *
 * @param first_time  First time value.
 * @param second_time Second time value.
 * @return            The function returns 0 for equal times, 1 if the first
 *                    time is greater than the second one and -1 the second time
 *                    is greater than the first one.
 */
int compare_timeval (struct timeval* first_time, struct timeval* second_time);

#endif // FLOW_UTIL_H
