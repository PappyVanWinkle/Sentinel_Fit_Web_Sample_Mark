/****************************************************************************\
**
** fit_node_locking.c
**
** Defines functionality for fetching fingerprint information for embedded devices.
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

#include <stddef.h>

#include "fit_dm_hash.h"
#include "fit_internal.h"
#include "fit_debug.h"
#include "fit_parser.h"
#include "fit_hwdep.h"
#include "fit_mem_read.h"
#include "fit_parser.h"

/* Function Definitions *****************************************************/

/**
 *
 * \skip fit_validate_fp_data
 *
 * This function is used to validate the fingerprint information present in license
 * data.
 *
 * @param IN    license     \n Pointer to fit_pointer_t structure containing license
 *                             data. To access the license data in different types of
 *                             memory (FLASH, E2, RAM), fit_pointer_t is used.
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_validate_fp_data(fit_pointer_t *license)
{
    fit_status_t status             = FIT_STATUS_UNKNOWN_ERROR;
    fit_context_data_t context;
    fit_pointer_t fitptr;

#ifdef FIT_USE_NODE_LOCKING
    fit_boolean_t valid_fp_present  = FIT_FALSE;
    fit_fingerprint_t licensefp;
    fit_fingerprint_t devicefp;
    fit_fp_callback callback_fn     = FIT_DEVICE_ID_GET;

    fit_memset((uint8_t *)&licensefp, 0, sizeof(fit_fingerprint_t));
    fit_memset((uint8_t *)&devicefp, 0, sizeof(fit_fingerprint_t));
#endif /* #ifdef FIT_USE_NODE_LOCKING */

    DBG(FIT_TRACE_INFO, "[fit_validate_fp_data]: license=0x%p length=%hd\n",
        license->data, license->length);
    fit_memset((uint8_t *)&context, 0 , sizeof(fit_context_data_t));
    fit_memset((uint8_t *)&fitptr, 0, sizeof(fit_pointer_t));

    fitptr.read_byte = license->read_byte;

    /* Check the presence of fingerprint in the license data.*/
    context.level = FIT_STRUCT_HEADER_LEVEL;
    context.index = FIT_FINGERPRINT_FIELD;
    context.operation = (uint8_t)FIT_OP_GET_DATA_ADDRESS;
    context.status = FIT_STATUS_OK;
    status = fit_parse_object(FIT_STRUCT_V2C_LEVEL, FIT_LICENSE_FIELD, license, &context);
    if (status != FIT_STATUS_OK)
        goto bail;

    if (context.parserstatus == FIT_INFO_STOP_PARSE && context.status == FIT_STATUS_LIC_FIELD_PRESENT)
    {
#ifndef FIT_USE_NODE_LOCKING
        DBG(FIT_TRACE_ERROR, "Fit core was not compiled with node locking macro \n");
        status = FIT_STATUS_NODE_LOCKING_NOT_SUPP;
        goto bail;
#else
        DBG(FIT_TRACE_ERROR, "Fingerprint information is found in license string.\n");
        /* get the fingerprint data in licensefp structure.*/
        fitptr.data = context.parserdata.addr;
        fit_get_fingerprint(&fitptr, &licensefp);

        /* License string contains the fingerprint data. Check the magic value.*/
        if (licensefp.magic == FIT_FP_MAGIC)
        {
            DBG(FIT_TRACE_INFO, "Magic number found in license string.\n");
            valid_fp_present = FIT_TRUE;
            status = FIT_STATUS_OK;
        }
        else
        {
            DBG(FIT_TRACE_ERROR, "Invalid Magic number in license string.\n");
            status = FIT_STATUS_INVALID_V2C;
            goto bail;
        }
        /* Validate algorithm used */
        if (licensefp.algid != FIT_AES_FP_ALGID)
        {
            status = FIT_STATUS_UNKNOWN_FP_ALGORITHM;
            goto bail;
        }
#endif /* #ifndef FIT_USE_NODE_LOCKING */
   }

#ifdef FIT_USE_NODE_LOCKING
    if (valid_fp_present)
    {
        DBG(FIT_TRACE_INFO, "Get fingerprint information from respective hardware.\n");
        /*
         * Get fingerprint data of the device and then compare it data present in
         * the license.
         */
        status = fit_get_device_fpblob(&devicefp, callback_fn);
        if (status != FIT_STATUS_OK)
        {
            DBG(FIT_TRACE_INFO, "Error in getting fingerprint data with status "
                "%d \n", status);
            goto bail;
        }
        if (devicefp.algid != FIT_AES_FP_ALGID)
        {
            status = FIT_STATUS_UNKNOWN_FP_ALGORITHM;
            goto bail;
        }

        if(fit_memcmp(licensefp.hash, devicefp.hash, FIT_DM_HASH_SIZE) != 0 )
        {
            DBG(FIT_TRACE_ERROR, "Fingerprint hash does not match with stored "
                "hash in license \n");
            status = FIT_STATUS_FP_MISMATCH_ERROR;
            goto bail;
        }
        else
        {
            DBG(FIT_TRACE_INFO, "Device fingerprint match with stored fingerprint "
                "data in license string\n");
        }
    }
#endif /* #ifdef FIT_USE_NODE_LOCKING */

bail:
    return status;
}

#ifdef FIT_USE_NODE_LOCKING
/**
 *
 * \skip fit_get_fingerprint
 *
 * Get fingerprint data from fit_pointer_t structure and put into fit_fingerprint_t
 * structure.
 *
 * @param IN    fpdata  \n Pointer to fit_pointer_t structure that contains
 *                         fingerprint data.
 *
 * @param OUT   fpstruct    \n Pointer to fit_fingerprint_t that needs to be
 *                             initialized.
 *
 */
void fit_get_fingerprint(fit_pointer_t *fpdata, fit_fingerprint_t *fpstruct)
{
    fit_pointer_t fitptr;

    fit_memset((uint8_t *)&fitptr, 0, sizeof(fit_pointer_t));
    /* Get first four bytes of fingerprint data. This will represent magic id.*/
    fpstruct->magic = read_dword(fpdata->data, fpdata->read_byte);
    /* Read algorith id value.*/
    fpstruct->algid = (uint8_t)read_dword(fpdata->data + sizeof(uint32_t), fpdata->read_byte);

    /* Get device id hash value*/
    fitptr.data = fpdata->data+sizeof(uint32_t)+sizeof(uint32_t);
    fitptr.length = FIT_DM_HASH_SIZE;
    fitptr.read_byte = fpdata->read_byte;
    fitptr_memcpy(fpstruct->hash, &fitptr);
}
#endif /* ifdef FIT_USE_NODE_LOCKING */

/**
 *
 * \skip fit_get_device_fpblob
 *
 * This function will fetch fingerprint/deviceid for the respective board. This will
 * call the hardware implemented callback function which will give raw data that would
 * be unique to each device. Raw data would be then hash with Daview Meyer hash function.
 *
 * @param OUT   fp  \n Pointer to fingerprint data that need to be filled in.
 *
 * @param IN    callback_fn     \n hardware implemented callback function that will
 *                                 return raw fingerprint data and its length.
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_get_device_fpblob(fit_fingerprint_t *fp, fit_fp_callback callback_fn)
{
    uint8_t rawdata[FIT_DEVID_MAXLEN]; /* Maximum length of device id is 64 bytes.*/
    uint8_t dmhash[FIT_DM_HASH_SIZE];
    fit_pointer_t fitptr;
    fit_status_t status = FIT_STATUS_UNKNOWN_ERROR;
    uint16_t datalen    = 0;
    uint16_t cntr       = 0;

    if( callback_fn == NULL )
        return FIT_STATUS_INVALID_PARAM;

    fit_memset(rawdata, 0, sizeof(rawdata));
    fit_memset(dmhash, 0, sizeof(dmhash));
    fit_memset((uint8_t *)&fitptr, 0, sizeof(fit_pointer_t));
    /* Initialize read pointer function.*/
    fitptr.read_byte = (fit_read_byte_callback_t )fit_read_ram_u8;

    /* Get the hardware fingerprint data.*/
    status = callback_fn(rawdata, sizeof(rawdata), &datalen);
    if (status != FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_ERROR, "Error in getting fingerprint data with status %d\n", status);
        return status;
    }
    /* device id length should be in range 4-64 characters. */
    if (datalen < FIT_DEVID_MINLEN || datalen > FIT_DEVID_MAXLEN)
        return FIT_STATUS_INVALID_DEVICE_ID_LEN;

    /* Print fingerprint raw data */
    for (cntr=0; cntr<datalen; cntr++) DBG(FIT_TRACE_INFO, "%X ", rawdata[cntr]);
    DBG(FIT_TRACE_INFO, "\n");

    fitptr.length = datalen;
    fitptr.data = (uint8_t *)rawdata;
    /* Get the Davies Meyer hash of fingerprint data.*/
    status = fit_davies_meyer_hash(&fitptr, (uint8_t *)&dmhash);
    if (status != FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_ERROR, "Error in getting Davies Meyer hash with status %d\n", status);
        return status;
    }

    /* Print fingerprint hash data (Davies Meyer Hash) */
    DBG(FIT_TRACE_INFO, "\nDavies Meyer hash of fingerprint data: ");
    for (cntr=0; cntr<FIT_DM_HASH_SIZE; cntr++) DBG(FIT_TRACE_INFO, "%X ", dmhash[cntr]);
    DBG(FIT_TRACE_INFO, "\n");

    /* Fill fingerprint data.*/
    fp->algid = FIT_AES_FP_ALGID; /* AES algorithm used for davies meyer hash function.*/
    fp->magic = FIT_FP_MAGIC; /* 'fitF' Magic no.*/
    fit_memcpy(fp->hash, dmhash, FIT_DM_HASH_SIZE); /* copy fingerprint hash data.*/

    return status;
}

