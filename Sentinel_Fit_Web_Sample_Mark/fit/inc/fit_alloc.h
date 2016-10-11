/****************************************************************************\
**
** fit_alloc.h
**
**
** Copyright (C) 2016, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#ifndef __FIT_ALLOC_H__
#define __FIT_ALLOC_H__

/* Required Includes ********************************************************/

#if !defined(FIT_CONFIG_FILE)
#include "fit_config.h"
#else
#include FIT_CONFIG_FILE
#endif

#ifdef FIT_DEBUG_HEAP
extern int  max_alloc;
extern int  curr_alloc;
extern int  n_alloc;
extern int  err_alloc;
#endif

void *fit_calloc(int nitems, int size);
void fit_free(void *ptr);

#endif /* __FIT_ALLOC_H__ */
