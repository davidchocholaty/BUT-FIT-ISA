/**********************************************************/
/*                                                        */
/* File: util.c                                           */
/* Created: 2022-10-01                                    */
/* Last change: 2022-10-01                                */
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

/*
 * TODO
 */
bool is_numeric_string(char* string)
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
 * @param string Input string
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
 * @param string Input string
 * @return       If string doesn't contain uint32_t number: 0L,
 *               number in uint32_t data type otherwise.
 */
uint16_t strtoui_32 (char* string)
{
    if (!is_numeric_string(string))
    {
        return 0L;
    }

    unsigned long numeric_value = strtoul(string, NULL, 10);

    return (numeric_value > UINT32_MAX) ? 0L : numeric_value;
}

/*
 * TODO
 */
bool in_range (const unsigned int value,
               const unsigned int min,
               const unsigned int max)
{
    return ((value - max) * (value - min) <= 0);
}
