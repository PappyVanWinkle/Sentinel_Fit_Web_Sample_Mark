/****************************************************************************\
**
** fit_uart.c
**
** UART output functions - TM4C1294XL version
**
** Copyright (C) 2016, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#include <energia.h>
#include <fit/hwdep/tm4c1294xl_energia/fit_uart.h>
#include <stdarg.h>

#include <stdint.h>
#include <stdbool.h>




#ifdef DEBUG
void __error__(char *pcFilename, uint32_t ui32Line) { }
#endif


/**
 * fit_uart_init
 *
 * initialize UART
 *
 */

void fit_uart_init(unsigned int baudrate)
{

    Serial.begin(115200);
    Serial.println();
}

/**
 * fit_uart_putc
 *
 * transmit byte to UART
 *
 * @param data -> byte to be transmitted
 */

void fit_uart_putc ( unsigned char data )
{
    Serial.write(data);
}

