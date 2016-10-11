/****************************************************************************\
**
** fit_alloc.h
**
**
** Copyright (C) 2016, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

/* Required Includes ********************************************************/

#if !defined(FIT_CONFIG_FILE)
#include "fit_config.h"
#else
#include FIT_CONFIG_FILE
#endif

#include <stdlib.h>
#include <string.h>

#include "fit_alloc.h"

#ifndef FIT_DEBUG_HEAP

void *fit_calloc(int nitems, int size)
{
    return calloc(nitems, size);
}

void fit_free(void *ptr)
{
    free(ptr);
}

#else

int alloc_size[1000] = {0};
void *alloc_ptr[1000] = {NULL};
int  max_alloc = 0;
int  curr_alloc = 0;
int  n_alloc = 0;
int  err_alloc = 0;

void *fit_calloc(int nitems, int size)
{
    int i;
    void *p;

    p = calloc(nitems, size);
    if (p) {
        ++n_alloc;
        for (i=0; i<1000; i++) {
            if (alloc_size[i] == 0) {
               alloc_size[i] = nitems * size;
               alloc_ptr[i] = p;
               curr_alloc+= nitems * size;
               if (curr_alloc > max_alloc) max_alloc = curr_alloc;
               break;
            }
        }
    } else {
      ++err_alloc;
    }

    return p;
}

void fit_free (void *ptr)
{
    int i;

    for (i=0; i<1000; i++) {
      if (alloc_ptr[i] == ptr) {
        curr_alloc-= alloc_size[i];
        alloc_size[i] = 0;
        alloc_ptr[i] = NULL;
        free(ptr);
        return;
      }
    }

    free(ptr);
    ++err_alloc;
}

#endif
