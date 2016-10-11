/****************************************************************************\
**
** util.h
**
** utility functions for Sentinel Fit web demo
**
** Copyright (C) 2016, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#ifndef __UTIL_H__
#define __UTIL_H__

#include <energia.h>
#include <stdarg.h>
#include <Ethernet.h>
#include <EthernetUdp.h>

#include "fit_types.h"
#include "fit_hwdep.h"

/**************************************************************************************************/

/**
 * Locations & size of licensing data in EEPROM
 */

#define EE_V2C_OFFSET  0
#define EE_V2C_MAXSIZE 4096

#define EE_AES_OFFSET  (EE_V2C_OFFSET + EE_V2C_MAXSIZE)
#define EE_AES_MAXSIZE 512

#define EE_RSA_OFFSET  (EE_AES_OFFSET + EE_AES_MAXSIZE)
#define EE_RSA_MAXSIZE 1024

/**************************************************************************************************/

EXTERNC void write_eeprom_u8 (int address, uint8_t value);

void      fit_ptr_dump (fit_pointer_t *fp);
uint8_t   read_0 (const uint8_t *p);
void      set_fit_ptr_ee (fit_pointer_t *fp, uint32_t offset, uint32_t maxsize );
void      set_fit_ptr_ram (fit_pointer_t *fp, uint8_t *data, uint32_t size);
void      ee_v2c_dump (void);
int       blob_write_ee (uint32_t ofs, uint32_t max, char *start, uint32_t size);
void      dump_ram (uint8_t *data, uint32_t size);

void      trim(char* s);

char*     iptoa (IPAddress ip, char* buf);
IPAddress atoip ( char* addr );
void      get_mac_address (char *mac);

void      pr(const char *format, ...);

#endif
