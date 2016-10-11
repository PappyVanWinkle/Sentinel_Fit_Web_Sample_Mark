/****************************************************************************\
**
** fit_memory.c
**
** Contains memory related function declaration for TM4C1294XL RAM/Flash version
**
**
** Copyright (C) 2016, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#include "fit_types.h"
#include <inttypes.h>


/**
 *
 * read_ram_u8
 *
 * Reads 1 byte data from data pointer passed in.
 *
 * @param   p --> pointer to data.
 *
 */
uint8_t read_ram_u8 (const uint8_t *p)
{
    return (uint8_t)*p;
}
