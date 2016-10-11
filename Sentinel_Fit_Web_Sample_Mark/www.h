/****************************************************************************\
**
** www.h
**
** Generates web pages
**
** Copyright (C) 2016, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#ifndef __WWW_H__
#define __WWW_H__

#include <energia.h>
#include <stdarg.h>
#include <driverlib/eeprom.h>

#include "util.h"

#include "fit_config.h"
#include "fit.h"
#include "fit_debug.h"
#include "fit_demo_getinfo.h"

/********************************************************************************************/

extern fit_key_array_t *key_arr;

EXTERNC void set_key_array (void);
EXTERNC fit_status_t do_consume_license(uint16_t feature_id);

/********************************************************************************************/

void www_server_init(void);
void do_www(void);

#endif
