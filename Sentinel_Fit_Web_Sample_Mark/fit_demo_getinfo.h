/****************************************************************************\
**
** fit_demo_getinfo.h
**
** Defines functionality for get info API on sentinel fit based licenses for
** embedded devices.
**
** Copyright (C) 2016, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#ifndef SENTINEL_FIT_WEB_SAMPLE_MARK_FIT_DEMO_GETINFO_H_
#define SENTINEL_FIT_WEB_SAMPLE_MARK_FIT_DEMO_GETINFO_H_

#include "fit_types.h"

/*
EXTERNC fit_status_t fit_testgetinfodata(
                          fit_pointer_t *licenseData,
                          uint8_t *pgetinfo,
                          uint16_t *getinfolen);
*/

EXTERNC fit_status_t fit_testgetinfodata_json(
                          fit_pointer_t *licenseData,
                          uint8_t *pgetinfo,
                          uint16_t *getinfolen);

#endif /* SENTINEL_FIT_WEB_SAMPLE_MARK_FIT_DEMO_GETINFO_H_ */
