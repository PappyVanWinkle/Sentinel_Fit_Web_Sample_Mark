/****************************************************************************\
**
** fit_eeprom_mem.c
**
** Contains memory(EEPROM) related function definitions for at90usbkey2 board.
** 
** Copyright (C) 2016, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#include "Energia.h"
#include "driverlib/eeprom.h"


//#include <stdint.h>
//#include "driverlib/rom.h"
//#include "driverlib/rom_map.h"

/**
 *
 * read_eeprom_u8
 *
 * Reads 1 byte data from data pointer passed in.
 *
 * @param   p --> pointer to data.
 *
 */

uint8_t read_eeprom_u8 (const uint8_t *p)
{
    uint32_t x = 0;
    uint32_t addr = (uint32_t)p;
    uint32_t byteAddr = addr - (addr % 4);

    ROM_EEPROMRead(&x, byteAddr, 4);
    x = x >> (8*(addr % 4));

    return (uint8_t) x;
}

void write_eeprom_u8 (int address, uint8_t value)
{
    uint32_t byteAddr = address - (address % 4);
    uint32_t x = 0, y;

    ROM_EEPROMRead(&x, byteAddr, 4);
    y = x;
    y &= ~(0xFF << (8*(address % 4)));
    y += value << (8*(address % 4));

    if (x != y) {
        ROM_EEPROMProgram(&y, byteAddr, 4);
    }
}

