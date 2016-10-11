/****************************************************************************\
**
** fit_consume.h
**
** Contains declaration for macros, constants and functions for consuming licenses
** for embedded devices.
**
** Copyright (C) 2016, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#ifndef __FIT_CONSUME_LIC_H__
#define __FIT_CONSUME_LIC_H__

/* Required Includes ********************************************************/
#include "fit_types.h"

/* Constants ****************************************************************/

/* Forward Declarations *****************************************************/

/* Types ********************************************************************/

/* Function Prototypes ******************************************************/

/*
 * This function will check whether feature_id is present in the license string that
 * is passed to the function.
 */
fit_status_t fit_find_feature_id(fit_pointer_t *pdata,
                                 uint8_t level,
                                 uint8_t index,
                                 uint16_t length,
                                 void *context);

/** This function is used for getting algorithm id used for signing license data. */
fit_status_t fit_get_license_sign_algid(fit_pointer_t *license, uint32_t *algid);

#endif /* __FIT_CONSUME_LIC_H__ */

