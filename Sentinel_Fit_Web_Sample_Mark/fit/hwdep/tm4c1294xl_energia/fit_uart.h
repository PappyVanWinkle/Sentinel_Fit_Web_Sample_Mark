/*
 * fit_uart.h
 *
 *  Created on: 24.08.2016
 *      Author: axel_2
 */

#ifndef SENTINEL_FIT_WEB_SAMPLE_MARK_FIT_HWDEP_TM4C1294XL_ENERGIA_FIT_UART_H_
#define SENTINEL_FIT_WEB_SAMPLE_MARK_FIT_HWDEP_TM4C1294XL_ENERGIA_FIT_UART_H_

#include "fit_hwdep.h"

EXTERNC void fit_uart_init( unsigned int baudrate );
EXTERNC void fit_uart_putc( unsigned char data );


#endif /* SENTINEL_FIT_WEB_SAMPLE_MARK_FIT_HWDEP_TM4C1294XL_ENERGIA_FIT_UART_H_ */
