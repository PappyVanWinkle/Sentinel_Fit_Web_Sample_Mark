/****************************************************************************\
**
** fit_fingerprint.c
**
** get board fingerprint - TM4C1294XL version
**
** Copyright (C) 2016, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "fit_debug.h"
#include <driverlib/rom.h>
#include "fit_hwdep.h"


char fit_dev_id[FIT_DEVID_MAXLEN] = FIT_DEVICE_ID;
uint16_t fit_dev_id_len = sizeof(FIT_DEVICE_ID) - 1;

#if 0

fit_status_t fit_device_id_get(uint8_t *rawdata,
                               uint8_t rawdata_size,
                               uint16_t *datalen)
{
    DBG(FIT_TRACE_INFO, "Fetching deviceid for tiva board: ");

    memcpy(rawdata, fit_dev_id, fit_dev_id_len);
    *datalen = fit_dev_id_len;

    return FIT_STATUS_OK;
}

#else

extern char my_mac[64];

fit_status_t fit_device_id_get(uint8_t *rawdata,
                               uint8_t rawdata_size,
                               uint16_t *datalen)
{
  char     s[96];
  uint16_t len;

  snprintf(s, sizeof(s), "TM4C1294XL-%s", my_mac);

  len = strlen(s);
  if (len > rawdata_size) {
	  return FIT_STATUS_INVALID_DEVICE_ID_LEN;
  }

  memcpy(rawdata, s, len);
  *datalen = len;

  return FIT_STATUS_OK;
}

#endif
