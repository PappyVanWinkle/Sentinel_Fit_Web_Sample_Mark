/****************************************************************************\
**
** fit_mem_read.c
**
** Defines functionality for memory related operations for Sentinel fit project.
** 
** Copyright (C) 2016, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

/* Required Includes ********************************************************/

#if !defined(FIT_CONFIG_FILE)
#include "fit_config.h"
#else
#include FIT_CONFIG_FILE
#endif

#include "fit_mem_read.h"

/* Function Definitions *****************************************************/

/**
 *
 * read_byte
 *
 * Reads 1 byte data from data pointer passed in.
 *
 * @param   address --> pointer to data.
 * @param   clbk_read_byte --> function pointer to read byte.
 *
 */
uint8_t read_byte(const uint8_t *address,
                  fit_read_byte_callback_t clbk_read_byte)
{
    return clbk_read_byte(address);
}

/**
 *
 * read_license_word
 *
 * Reads 2 byte data from data pointer passed in.
 *
 * @param   address --> pointer to data.
 * @param   clbk_read_byte --> function pointer to read byte.
 *
 */
uint16_t read_word(const uint8_t *address,
                   fit_read_byte_callback_t clbk_read_byte)
{
    uint16_t x = 0;

    x = (uint16_t)clbk_read_byte(address); address++;
    x+= (uint16_t)clbk_read_byte(address) << 8;
    return x;
}

/**
 *
 * read_license_dword
 *
 * Reads 4 byte data (1 dword) from data pointer passed in.
 *
 * @param   address --> pointer to data.
 * @param   clbk_read_byte --> function pointer to read byte.
 *
 */
uint32_t read_dword(const uint8_t *address,
                    fit_read_byte_callback_t clbk_read_byte)
{
    uint32_t x;

    x = (uint32_t)clbk_read_byte(address); address++;
    x+= (uint32_t)((uint32_t)(clbk_read_byte(address))) << 8; address++;
    x+= (uint32_t)((uint32_t)(clbk_read_byte(address))) << 16; address++;
    x+= (uint32_t)((uint32_t)(clbk_read_byte(address))) << 24;
    return x;
}

/**
 *
 * fit_read_ram_u8
 *
 * Reads 1 byte data from data pointer passed in.
 *
 * @param   datap --> pointer to data.
 *
 */
uint8_t fit_read_ram_u8 (const uint8_t *datap)
{
    return (uint8_t)*datap;
}
