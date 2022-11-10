/**********************************************************/
/*                                                        */
/* File: util.c                                           */
/* Created: 2022-10-01                                    */
/* Last change: 2022-10-13                                */
/* Author: David Chocholaty <xchoch09@stud.fit.vutbr.cz>  */
/* Project: Project for the course ISA - variant 1        */
/*          - Generation of NetFlow data from captured    */
/*            network traffic.                            */
/* Description: Util for the NetFlow exporter             */
/*                                                        */
/**********************************************************/

#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "error.h"
#include "memory.h"

/*
 * Function to check if the input string is only from numeric characters.
 *
 * @param string Input string for check.
 */
bool is_numeric_string (char* string)
{
    for (char *i = string ; *i ; i++) {
        if (!isdigit(*i))
        {
            return false;
        }
    }

    return true;
}

/*
 * Function for convert string to uint16_t.
 *
 * @param string Input string.
 * @return       If string doesn't contain uint16_t number: 0L,
 *               number in uint16_t data type otherwise.
 */
uint16_t strtoui_16 (char* string)
{
    if (!is_numeric_string(string))
    {
        return 0L;
    }

    unsigned long numeric_value = strtoul(string, NULL, 10);

    return (numeric_value > UINT16_MAX) ? 0L : numeric_value;
}

/*
 * Function for convert string to uint32_t.
 *
 * @param string Input string.
 * @return       If string doesn't contain uint32_t number: 0L,
 *               number in uint32_t data type otherwise.
 */
uint32_t strtoui_32 (char* string)
{
    if (!is_numeric_string(string))
    {
        return 0L;
    }

    unsigned long numeric_value = strtoul(string, NULL, 10);

    return (numeric_value > UINT32_MAX) ? 0L : numeric_value;
}

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
               const unsigned int max)
{
    return ((value - max) * (value - min) <= 0);
}

uint8_t parse_name_port (char* in_source, char** out_name, char** out_port)
{
    uint8_t status;
    size_t characters_number;

    // Find the last occurrence of ':'.
    char* delimiter_addr = strrchr(in_source, ':');

    if (delimiter_addr == NULL)
    {
        // Does not contain optional port value (only name or value).
        out_port = NULL;
        status = allocate_string(out_name, strlen(in_source));

        if (status != NO_ERROR)
        {
            return MEMORY_HANDLING_ERROR;
        }

        strcpy(*out_name, in_source);
    }
    else
    {
        // Copy with skip of the ':' character in the result.
        status = allocate_string(out_port, strlen(delimiter_addr + 1));

        if (status != NO_ERROR)
        {
            return MEMORY_HANDLING_ERROR;
        }

        strcpy(*out_port, delimiter_addr + 1);

        // Copy the substring in front of ':'.
        characters_number = delimiter_addr - in_source + 1;
        status = allocate_string(out_name, characters_number);

        if (status != NO_ERROR)
        {
            return MEMORY_HANDLING_ERROR;
        }

        strncpy(*out_name, in_source, characters_number - 1);
        (*out_name)[characters_number - 1] = '\0';
    }

    return NO_ERROR;
}
