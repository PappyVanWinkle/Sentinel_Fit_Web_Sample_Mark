/****************************************************************************\
**
** fit_flash_mem.c
**
** Contains memory(flash) related function definitions for at90usbkey2 board.
** 
** Copyright (C) 2016, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#ifdef FIT_USE_FLASH

#include "fit_types.h"
#include <asf.h>

/**
 *
 * read_flash_u8
 *
 * Reads 1 byte data from data pointer passed in.
 *
 * @param   p --> pointer to data.
 *
 */
uint8_t read_flash_u8 (const uint8_t *p)
{
    return (uint8_t)pgm_read_byte_near(p);
}
#endif // #ifdef FIT_USE_FLASH
