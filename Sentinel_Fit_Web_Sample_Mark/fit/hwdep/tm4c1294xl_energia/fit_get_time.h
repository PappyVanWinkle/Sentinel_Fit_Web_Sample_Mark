/****************************************************************************\
**
** fit_get_time.h
**
** Contains function declaration related with expiration based licenses.
** 
** Copyright (C) 2016, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#ifndef __GETTIME_H__
#define __GETTIME_H__

#include "fit_types.h"

uint32_t fit_time_get  (void);
void     fit_time_set  (uint32_t settime);
uint32_t fit_time_init (void);

#endif
