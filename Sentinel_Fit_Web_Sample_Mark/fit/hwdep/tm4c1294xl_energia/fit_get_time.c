/****************************************************************************\
**
** fit_get_time.c
**
** Contains function declaration related with expiration based licenses.
** 
** Copyright (C) 2016, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#include <energia.h>
#include <fit/hwdep/tm4c1294xl_energia/fit_get_time.h>

#include "fit_debug.h"

static uint32_t unixtime;
static uint32_t ms_ticker = 0;
static int      ticker_registered = 0;

/**
 *
 * fit_time_get
 *
 * This function returns the current time for hardware board.
 *
 */
uint32_t fit_time_get (void)
{
    DBG(FIT_TRACE_INFO, "Get unix time %lu\n", unixtime);
    return unixtime;
}


/**
 *
 * fit_time_set
 *
 * This function set the current unix time for hardware board.
 *
 */
void fit_time_set (uint32_t settime)
{
    DBG(FIT_TRACE_INFO, "Set unix time %lu\n", settime);
    unixtime = settime;
}



static void my1msTicker(uint32_t ms)
{
  if (++ms_ticker >= 1000) {
      ms_ticker = 0;
      ++unixtime;
  }
}


 /**
  *
  * fit_time_init
  *
  * This function initializes an RTC
  * returns 0 for failure,
  *         1 for success
  *
  */

uint32_t fit_time_init (void)
{
    if (!ticker_registered) {
        ticker_registered = 1;
        registerSysTickCb(my1msTicker);
        return 1; /* OK */
    }
    return 0;
}
