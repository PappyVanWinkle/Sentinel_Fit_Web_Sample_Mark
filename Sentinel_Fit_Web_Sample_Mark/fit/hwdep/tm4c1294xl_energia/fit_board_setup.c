/****************************************************************************\
**
** fit_board_setup.c
**
** Contains function definitions for setting board for testing fit core code.
**
** Copyright (C) 2016, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#include <fit/hwdep/tm4c1294xl_energia/fit_get_time.h>
#include "fit_hwdep.h"


void fit_board_setup(void)
{
    fit_led_init();
    fit_uart_init(0);
    FIT_TIME_INIT();
}

