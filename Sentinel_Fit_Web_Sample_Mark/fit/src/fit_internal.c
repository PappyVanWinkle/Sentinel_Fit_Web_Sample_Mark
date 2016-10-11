/****************************************************************************\
**
** fit_internal.c
**
** Defines functionality for common function use across Sentinel fit project.
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

#ifdef FIT_USE_SYSTEM_CALLS
#include <string.h>
#endif

#include "fit_parser.h"
#include "fit_internal.h"
#include "fit_debug.h"
#include "fit_mem_read.h"
#include "fit_aes.h"
#include "fit_consume.h"
#include "fit_rsa.h"
#include "fit_omac.h"

#ifdef FIT_USE_NODE_LOCKING
#include "fit_dm_hash.h"
#endif /* ifdef FIT_USE_NODE_LOCKING */

/* Function Definitions *****************************************************/

/**
 *
 * \skip fit_get_key_data_from_keys
 *
 * This function is used to get key data (AES, RSA etc) corresponding t o algorithm
 * id passed in from license binary.
 *
 * @param IN    keys    \n Pointer to fit_key_array_t structure containing array of
 *                         key data and algorithms supported for each key.
 *
 * @param IN    algorithm   \n Algorithm id for which key data is to be fetch from
 *                             keys array.
 *
 * @param OUT   key     \n Pointer to fit_pointer_t structure that will contain
 *                         requested key data.
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_get_key_data_from_keys(fit_key_array_t *keys,
                                        uint32_t algorithm,
                                        fit_pointer_t *key)
{
    fit_status_t status = FIT_STATUS_KEY_NOT_PRESENT;
    uint16_t cntrx      = 0;
    uint16_t cntry      = 0;
    uint16_t keyscope   = 0;
    uint16_t algid      = 0;
    fit_key_data_t *keydata = NULL;
    fit_algorithm_list_t *algdata = NULL;

    if (keys == NULL || keys->read_byte == NULL)
        return FIT_STATUS_INVALID_PARAM;

    /** Check if presence of algorithm in fit_key_array_t data passed in.
      * if present then get the key data corresponding to algorithm id is put in fit_pointer_t
      * structure.
      */

    for (cntrx = 0; cntrx < keys->number_of_keys; cntrx++)
    {
        keydata = (fit_key_data_t *)(keys->keys[cntrx]);

        /* Validate the length of the key. */
        if (keydata->key_length == 0) {
        	continue;
        }

        /* Get the algorithm id and scope of the license. */
        algdata = (fit_algorithm_list_t *)keydata->algorithms;
        for (cntry = 0; cntry < algdata->num_of_alg; cntry++)
        {
            keyscope = (uint16_t)((uint16_t)*(algdata->algorithm_guid[cntry]) >> 12);
            algid = (uint16_t)((uint16_t)*(algdata->algorithm_guid[cntry]) & 0xFFF);

            if (!(keyscope >= FIT_KEY_SCOPE_SIGN && keyscope <= FIT_KEY_SCOPE_ID_MAX))
                return FIT_STATUS_INVALID_KEY_SCOPE;

            /* If match then initialize the fit_pointer_t structure with the key data  */
            if (algid == algorithm)
            {
                key->data = (uint8_t *)keydata->key;
                key->length = keydata->key_length;
                key->read_byte = keys->read_byte;
                status = FIT_STATUS_OK;
                goto key_found;
            }
        }
    }

key_found:
    return status;
}

/**
 *
 * \skip fit_verify_license
 *
 * This function is used to validate signature (AES, RSA etc) in the license binary.
 *
 * @param IN    license     \n Pointer to fit_pointer_t structure containing license
 *                             data. To access the license data in different types of
 *                             memory (FLASH, E2, RAM), fit_pointer_t is used.
 *
 * @param IN    keys    \n  Pointer to array of key data. Also contains callback
 *                          to read key data in different types of memory(FLASH, E2, RAM).
 *
 * @param IN    check_cache \n FIT_TRUE if signing verification is already done; FIT_FALSE
 *                             otherwise.
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_verify_license(fit_pointer_t *license,
                                fit_key_array_t *keys,
                                fit_boolean_t check_cache)
{
    fit_status_t status = FIT_STATUS_UNKNOWN_ERROR;
    uint32_t signalgid  = 0;
    fit_pointer_t key_data;

    DBG(FIT_TRACE_INFO, "[fit_verify_license]: Entry");
    /* Get the algorithm id used for signing the license from the license binary */
    status = fit_get_license_sign_algid(license, &signalgid);
    if (status != FIT_STATUS_OK)
        return status;

    /* Get key data corresponding to algid used in signing license binary */
    fit_memset((uint8_t *)&key_data, 0, sizeof(fit_pointer_t));
    status = fit_get_key_data_from_keys(keys, signalgid, &key_data);
    if (status != FIT_STATUS_OK)
        return status;

    if (signalgid == FIT_RSA_2048_ADM_PKCS_V15_ALG_ID)
    {
#ifdef FIT_USE_RSA_SIGNING
        /* Verify the license string against RSA signing and node locking */
        status = fit_verify_rsa_signature(license, &key_data, check_cache);
        if (status != FIT_STATUS_OK)
            return status;
#else
        return FIT_STATUS_NO_RSA_SUPPORT;
#endif // #ifdef FIT_USE_RSA_SIGNING
    }
    else if (signalgid == FIT_AES_128_OMAC_ALG_ID)
    {
#ifdef FIT_USE_AES_SIGNING
        /* Verify the license string against AES signing and node locking */
        status = fit_validate_omac_signature(license, &key_data);
        if (status != FIT_STATUS_OK)
            return status;
#else
        return FIT_STATUS_NO_AES_SUPPORT;
#endif // #ifdef FIT_USE_AES_SIGNING
    }

    DBG(FIT_TRACE_INFO, "[fit_verify_license]: Exit");
    return status;
}

/**
 *
 * \skip fit_memcpy
 *
 * Copies data from source to destination location.
 *
 * @param OUT   dst     \n Destination pointer where data need to copied.
 *
 * @param IN    src     \n Source pointer which need to be copied to destination
 *                         pointer
 *
 * @param IN    srclen  \n Length of data to be copied.
 *
 */
#ifndef FIT_USE_SYSTEM_CALLS
void fit_memcpy(uint8_t *dst, uint8_t *src, uint16_t srclen)
{
    uint16_t cntr = 0;

    for (cntr = 0; cntr < srclen; ++cntr)
        *dst++ = *src++;
}
#endif

/**
 *
 * \skip fitptr_memcpy
 *
 * Copies data from source to destination location. Source data comes from fit_pointer_t.
 *
 * @param OUT   dst     \n Destination pointer where data need to copied.
 *
 * @param IN    src     \n Pointer to fit_pointer_t that contains source data pointer
 *                         and length to be copied.
 *
 */
void fitptr_memcpy(uint8_t *dst, fit_pointer_t *src)
{
    uint16_t cntr = 0;

    for (cntr = 0; cntr < src->length; ++cntr)
        *dst++ = src->read_byte(src->data + cntr);
}

/**
 *
 * \skip fit_memcmp
 *
 * Compares data from two different memory address.
 *
 * @param IN    pdata1  \n Pointer to data1
 *
 * @param IN    pdata2  \n Pointer to data2
 *
 * @param IN    len     \n Length of data to be compared.
 *
 * @return 0 if pdata1 and pdata2 are same; otherwise return difference.
 *
 */
#ifndef FIT_USE_SYSTEM_CALLS
int16_t fit_memcmp(uint8_t *pdata1, uint8_t *pdata2, uint16_t len)
{
    uint16_t cntr = 0;

    for (cntr = 0; cntr < len; ++cntr)
    {
        if (*pdata1++ == *pdata2++)
            continue;
        else
        {
            return (len - cntr);
        }
    }

    return 0;
}
#endif

/**
 *
 * \skip fit_memset
 *
 * Initialize data with value passed in.
 *
 * @param IN    pdata   \n Pointer to data to be initialize.
 *
 * @param IN    value   \n Value to assign to pdata.
 *
 * @param IN    len     \n Length of pdata to be initialized.
 *
 */
#ifndef FIT_USE_SYSTEM_CALLS
void fit_memset(uint8_t *pdata, uint8_t value, uint16_t len)
{
    uint16_t cntr = 0;

    for (cntr = 0; cntr < len; ++cntr)
    {
        *pdata = value;
        pdata++;
    }
}
#endif
