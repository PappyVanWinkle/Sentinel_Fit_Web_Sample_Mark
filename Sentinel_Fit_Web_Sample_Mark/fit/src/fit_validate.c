/****************************************************************************\
**
** fit_validate.c
**
** Defines functionality for validate license for embedded devices.
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

#include "stddef.h"
#include "fit_debug.h"
#include "fit_internal.h"

/* Function Definitions *****************************************************/

/**
 *
 * \skip fit_licenf_validate_license
 *
 * This function is used to validate following:
 *      1. RSA signature of new license.
 *      2. New license node lock verification.
 *
 * @param IN    license     \n Pointer to fit_pointer_t structure containing license
 *                             data. To access the license data in different types
 *                             of memory (FLASH, E2, RAM), fit_pointer_t is used.
 *
 * @param IN    keys    \n Pointer to array of key data. Also contains callback
 *                         function to read key data in differenttypes of memory
 *                         (FLASH, E2, RAM).
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_licenf_validate_license(fit_pointer_t *license,
                                         fit_key_array_t *keys)
{
    fit_status_t status = FIT_STATUS_UNKNOWN_ERROR;

    DBG(FIT_TRACE_INFO, "[fit_validate_license]: pdata=0x%p \n", license->data);

    if (license->read_byte == NULL)
        return FIT_STATUS_INVALID_PARAM_1;

    if (keys->read_byte == NULL)
        return FIT_STATUS_INVALID_PARAM_2;

    /** Verify the license string against signing key data present in keys array
      * and node locking 
      */
    status = fit_verify_license(license, keys, FIT_FALSE);

    return status;
}

