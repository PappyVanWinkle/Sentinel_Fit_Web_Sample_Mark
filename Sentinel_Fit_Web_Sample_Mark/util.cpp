/****************************************************************************\
**
** util.c
**
** utility functions for Sentinel Fit webdemo
**
** Copyright (C) 2016, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#include "util.h"

/**************************************************************************************************/

extern "C" void fit_putc(char c);

/**************************************************************************************************/

void trim(char* s)
{
    char* begin = s;
    char* end = s + strlen(s);

    while (begin < end && (unsigned char) begin[0] <= ' ')
        ++begin;

    while (begin < end && (unsigned char) end[-1] <= ' ')
        --end;

    *end = 0;

    if (begin != s) {
        memmove(s, begin, end - begin + 1); /* copy also the ending 0 */
    }
}

/**************************************************************************************************/

void get_mac_address(char *mac)
{
    uint32_t ui32User0, ui32User1;
    uint8_t m1, m2, m3, m4, m5, m6;

    ROM_FlashUserGet(&ui32User0, &ui32User1);
    m1 = (ui32User0 >> 0) & 0xff;
    m2 = (ui32User0 >> 8) & 0xff;
    m3 = (ui32User0 >> 16) & 0xff;
    m4 = (ui32User1 >> 0) & 0xff;
    m5 = (ui32User1 >> 8) & 0xff;
    m6 = (ui32User1 >> 16) & 0xff;

    sprintf(mac, "%02X-%02X-%02X-%02X-%02X-%02X", m1, m2, m3, m4, m5, m6);
}

/**************************************************************************************************/

char* iptoa(IPAddress ip, char* buf)
{
    sprintf(buf, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
    return buf;
}


IPAddress atoip(char* addr)
{
    uint32_t x1, x2, x3, x4;
    char st[64];
    char *s = (char*) &st;

    if (addr == 0)
        return IPAddress(0, 0, 0, 0);

    strncpy(s, addr, 60);
    strncat(s, ".....", 60);

    x1 = atoi(s);
    while (*s++ != '.')
        ;
    x2 = atoi(s);
    while (*s++ != '.')
        ;
    x3 = atoi(s);
    while (*s++ != '.')
        ;
    x4 = atoi(s);

    return IPAddress(x1, x2, x3, x4);
}

/***************************************************************************************************************/

void pr(const char *format, ...)
{
    char write_buffer[1024] = { 0 };
    char *s = write_buffer;
    uint16_t len = 0;
    va_list arg;

    va_start(arg, format);
    len = vsnprintf(write_buffer, sizeof(write_buffer), format, arg);
    va_end(arg);

    if (len) {
        while (*s)
            fit_putc(*s++);
    }
}

/***************************************************************************************************************/

static void prln(void)
{
    pr("-------------------------------------------------------------------------------\n");
}

void fit_ptr_dump(fit_pointer_t *fp)
{
    uint8_t b;
    int i, col;
    uint8_t *data;

    prln();
    pr("size: %u\n", fp->length);

    col = 0;
    data = fp->data;
    pr(" %04X: ", data);
    for (i = 0; i < fp->length; i++) {
        b = fp->read_byte(data);
        data++;
        pr("%02X ", b);
        if (++col > 15) {
            pr("\n %04X: ", data);
            col = 0;
        }
    }
    if (col)
        pr("\n");

    prln();
}

/**************************************************************************************************/

void dump_ram(uint8_t *data, uint32_t size)
{
    uint8_t b;
    uint32_t i, col, ofs;

    prln();
    pr("size: %u\n", size);

    col = 0;
    ofs = 0;
    pr(" %04X: ", ofs);
    for (i = 0; i < size; i++) {
        b = *data;
        data++;
        ofs++;
        pr("%02X ", b);
        if (++col > 15) {
            pr("\n %04X: ", ofs);
            col = 0;
        }
    }
    if (col)
        pr("\n");

    prln();
}

/**************************************************************************************************/

uint8_t read_0(const uint8_t *p)
{
    return 0;
}

/**************************************************************************************************/

void set_fit_ptr_ee(fit_pointer_t *fp, uint32_t offset, uint32_t maxsize)
{
    uint32_t size;

    size = read_eeprom_u8((uint8_t*) offset++);
    size += read_eeprom_u8((uint8_t*) offset++) << 8;
    size += read_eeprom_u8((uint8_t*) offset++) << 16;
    size += read_eeprom_u8((uint8_t*) offset++) << 24;
    if ((size < 4) || (size > maxsize)) {
        fp->length = 0;
        fp->data = 0;
        fp->read_byte = (fit_read_byte_callback_t) read_0;
    } else {
        fp->length = size;
        fp->data = (uint8_t*) offset;
        fp->read_byte = (fit_read_byte_callback_t) read_eeprom_u8;
    }
}

/**************************************************************************************************/

void ee_v2c_dump(void)
{
    fit_pointer_t fp;
    set_fit_ptr_ee(&fp, EE_V2C_OFFSET, EE_V2C_MAXSIZE);
    fit_ptr_dump(&fp);
}

/**************************************************************************************************/

void set_fit_ptr_ram(fit_pointer_t *fp, uint8_t *data, uint32_t size)
{
    fp->length = size;
    fp->data = data;
    fp->read_byte = (fit_read_byte_callback_t) FIT_READ_BYTE_RAM;
}

/**************************************************************************************************/

int blob_write_ee(uint32_t ofs, uint32_t max, char *start, uint32_t size)
{
    uint32_t i, addr;
    uint8_t data;

    if (size + 4 > max) {
        pr("Object to be written to EE is to big.\n");
        return 0;
    }

    addr = ofs; /* offset into EE space */
    write_eeprom_u8(addr++, (size) & 0xFF);
    write_eeprom_u8(addr++, (size >> 8) & 0xFF);
    write_eeprom_u8(addr++, (size >> 16) & 0xFF);
    write_eeprom_u8(addr++, (size >> 24) & 0xFF);

    for (i = 0; i < max - 4; i++) {
        if (i < size)
            data = *(start + i);
        else
            data = 0;
        write_eeprom_u8(addr, data);
        addr++;
    }

    return 1;
}

/**************************************************************************************************/

