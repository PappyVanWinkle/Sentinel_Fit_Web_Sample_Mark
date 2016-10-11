/****************************************************************************\
**
** fit_consume.c
**
** Defines functionality for consuming licenses for embedded devices.
** 
** Copyright (C) 2016, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#if !defined(FIT_CONFIG_FILE)
#include "fit_config.h"
#else
#include FIT_CONFIG_FILE
#endif

#ifdef FIT_USE_SYSTEM_CALLS
#include <string.h>
#endif

#include "fit_internal.h"
#include "fit_parser.h"
#include "fit_hwdep.h"
#include "fit_debug.h"
#include "fit_mem_read.h"

/**
 *
 * \skip fit_find_feature_id
 *
 * This function will check whether license data contains the feature_id that is
 * passed to the function.. If license contains the requested feature_id value
 * then this function will sends FIT_STOP_PARSING status.
 *
 * @param IN    pdata   \n Pointer to data that contains feature id value.
 *
 * @param IN    level   \n level/depth of license schema.
 *
 * @param IN    index   \n Structure index in license schema.
 *
 * @param IN    length  \n Length of the requested information in bytes.
 *
 * @param IO    context \n Core Fit context data.
 *
 */
fit_status_t fit_find_feature_id(fit_pointer_t *pdata,
                                 uint8_t level,
                                 uint8_t index,
                                 uint16_t length,
                                 void *context)
{
    uint32_t integer            = 0;
    fit_context_data_t *pcontext  = (fit_context_data_t *)context;
    /* Get the field type corresponding to level and index.*/
    wire_type_t type            = get_field_type(level, index);

    if (type != FIT_INTEGER)
    {
        pcontext->parserstatus = FIT_INFO_CONTINUE_PARSE;
        return FIT_STATUS_OK;
    }
    if (pdata == NULL)
        return FIT_STATUS_INVALID_PARAM_1;
    if (context == NULL)
        return FIT_STATUS_INVALID_PARAM_5;

    DBG(FIT_TRACE_INFO, "[fit_find_feature_id]: level=%d, index=%d, type=%d, pdata=%08p # \n",
        level, index, type, pdata->data);

    DBG(FIT_TRACE_INFO, "Looking for Feature ID: %u\n", pcontext->parserdata.id);

    /* Check we are at correct level and index.*/
    if (level == FIT_STRUCT_FEATURE_LEVEL && index == FIT_ID_FEATURE_FIELD)
    {
        /* Get integer value. Integer value can be 16 bit value or 32 bit value.*/
        if (length == sizeof(uint16_t))
            integer = (read_word(pdata->data, pdata->read_byte)/2)-1;
        else if (length == sizeof(uint32_t))
            integer = read_dword(pdata->data, pdata->read_byte);

        /* Check if this feature id is what we are looking for.*/
        if (((fit_context_data_t *)pcontext)->parserdata.id == integer)
        {
            DBG(FIT_TRACE_INFO, "Feature id %u is present.\n", integer);
            ((fit_context_data_t *)pcontext)->status = FIT_INFO_FEATURE_ID_FOUND;
            ((fit_context_data_t *)pcontext)->parserstatus = FIT_INFO_STOP_PARSE;
        }
    }

    return FIT_STATUS_OK;
}

/**
 *
 * \skip fit_getunixtime
 *
 * This function is used for calling hardware dependent callback fn which will
 * return the current time in unix. If callback function is NULL or not defined
 * then return "license expiration not supported" error.
 *
 * @param IO    unixtime    \n Pointer to integer that will contain the current time.
 *
 */
fit_status_t fit_getunixtime(uint32_t *unixtime)
{
#ifdef FIT_USE_CLOCK
    uint32_t time;

    /* Return error if time clock functions were not implemented */
    if (FIT_TIME_GET == NULL )
        return FIT_STATUS_LIC_EXP_NOT_SUPP;

    /* Call hardware board specific time function */
    time = FIT_TIME_GET();
    *unixtime = time;

    return FIT_STATUS_OK;
#else
    return FIT_STATUS_NO_CLOCK_SUPPORT;
#endif
}

/**
 *
 * \skip fit_get_license_sign_algid
 *
 * This function is used for getting algorithm id that was used for signing
 * license data.
 *
 * @param IN    license    \n Pointer to fit_pointer_t structure containing license
 *                            data. To access the license data in different types of
 *                            memory (FLASH, E2, RAM), fit_pointer_t is used.
 *
 * @param OUT   algid       \n On return this will contain algorithm id used to sign
 *                             license data.
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_get_license_sign_algid(fit_pointer_t *license, uint32_t *algid)
{
    fit_status_t status     = FIT_STATUS_UNKNOWN_ERROR;
    fit_pointer_t fitptr;
    fit_context_data_t context;

    DBG(FIT_TRACE_INFO, "[fit_get_license_sign_algid]: license=0x%p \n", license->data);

    /* Validate parameters.*/
    if (license->read_byte == NULL)
        return FIT_STATUS_INVALID_PARAM;

    fit_memset((uint8_t *)&context, 0 , sizeof(fit_context_data_t));
    fit_memset((uint8_t *)&fitptr, 0, sizeof(fit_pointer_t));
    fitptr.read_byte = license->read_byte;

    /* Get algorithm used for signing license.*/
    context.level = FIT_STRUCT_SIGNATURE_LEVEL;
    context.index = FIT_ALGORITHM_ID_FIELD;
    context.operation = (uint8_t)FIT_OP_GET_DATA_ADDRESS;

    /* Logix of getting algid will change if licgen supports multiple algorithms
     * in one license binary
     */
    /* Parse license data to get address where algorithm data is stored */
    status = fit_parse_object(FIT_STRUCT_V2C_LEVEL, FIT_LICENSE_FIELD, license,
        &context);
    if (status == FIT_STATUS_OK && context.parserstatus == FIT_INFO_STOP_PARSE &&
            context.status == FIT_STATUS_LIC_FIELD_PRESENT)
    {
        *algid = (uint32_t)(read_word(context.parserdata.addr, license->read_byte)/2)-1;
        status = FIT_STATUS_OK;
    }
    else
    {
        DBG(FIT_TRACE_ERROR, "Not able to get algorithm data used for license "
            "signing %d\n", (fit_status_t)context.status);
        status = FIT_STATUS_INVALID_V2C;
    }

    return status;
}

/**
 *
 * \skip fit_get_lic_prop_data
 *
 * This function is used for parse license property present in data passed in and
 * fill in fit_licensemodel_t structure.
 *
 * @param IN    pdata   \n Pointer to license property structure data.
 *
 * @param OUT   licmodel    \n Pointer to structure that will contain license property
 *                             data against data passed in.
 *
 */
static fit_status_t fit_get_lic_prop_data(fit_pointer_t *pdata, fit_licensemodel_t *licmodel)
{
    uint16_t cntr       = 0;
    /*
     * Skip_fields represents number of fields to skip or number of fields that
     * does not have any data in license binary.
     */
    uint8_t skip_fields = 0;
    uint8_t cur_index   = 0;
    uint8_t index       = 0;
    uint8_t *temp       = pdata->data;
    /* Get the number of fields present in license property data */
    uint16_t num_fields = read_word(pdata->data, pdata->read_byte);
    uint16_t field_data = 0;
    uint16_t struct_offset  = (num_fields+1)*FIT_PFIELD_SIZE;

    DBG(FIT_TRACE_INFO, "[fit_get_lic_prop]: pdata=%08p # \n", pdata);

    if (licmodel == NULL)
        return FIT_STATUS_INVALID_PARAM_2;

    /* Move data pointer to next field.*/
    pdata->data   = pdata->data + FIT_PFIELD_SIZE;

    /* Parse all fields data in a structure.*/
    for( cntr = 0; cntr < num_fields; cntr++)
    {
        field_data = read_word(pdata->data, pdata->read_byte);
        /* If field_data is zero, that means the field data is encoded in data part.*/
        if( field_data == 0 )
        {
            index = cur_index;
            /* Go to next index value.*/
            cur_index++;
        }
        /*
         * If value of field_data is odd, that means the tags is not continuous i.e.
         * we need to skip fields by (field_data+1)/2 .
         */
        else if( field_data & 1)
        {
            index = cur_index;
            skip_fields  = (uint8_t)(field_data+1)/2;
            /* skip the fields as it does not contain any data in V2C.*/
            cur_index    = cur_index + skip_fields;
        }
        /* field_data contains the field value */
        else if(field_data%2 == 0)
        {
            index = cur_index;
            /* Go to next index value.*/
            cur_index++;
        }

        if (index == FIT_FEATURE_FIELD)
        {
            /* Skip the data part as we are not interested in feature data here */
            struct_offset   = (uint16_t)(struct_offset +
                (uint16_t)read_dword(temp+struct_offset, pdata->read_byte) +
                sizeof(uint32_t));
        }
        else if (index == FIT_PERPETUAL_FIELD)
        {
            /* Get the perpetual value */
            licmodel->isperpetual = 
                (fit_boolean_t)(read_word(pdata->data, pdata->read_byte)/2 - 1);
        }
        else if (index == FIT_START_DATE_FIELD)
        {
            /* Start date is present in license string */
            licmodel->isstartdate = FIT_TRUE;
            /* Get the time when license is generated i.e. date when license is created */
            licmodel->startdate = read_dword((temp+struct_offset)+sizeof(uint32_t),
                pdata->read_byte);

            /* 
             * Get to next field data value (for those fields for which field data
             * is encoded in data part.
             */
            struct_offset   = (uint16_t)(struct_offset +
                (uint16_t)read_dword(temp+struct_offset, pdata->read_byte) +
                sizeof(uint32_t));
        }
        else if (index == FIT_END_DATE_FIELD)
        {
            /* license is time expiration based license */
            licmodel->isenddate = FIT_TRUE;
            /* Get the expiration time i..e time by which license would get expired. */
            licmodel->enddate = read_dword((temp+struct_offset)+sizeof(uint32_t),
                pdata->read_byte);

            /* 
             * Get to next field data value (for those fields for which field data
             * is encoded in data part.
             */
            struct_offset   = (uint16_t)(struct_offset +
                (uint16_t)read_dword(temp+struct_offset, pdata->read_byte) +
                sizeof(uint32_t));
        }

        /* Move data pointer to next field.*/
        pdata->data = pdata->data + FIT_PFIELD_SIZE;
    }

    pdata->data = temp;

    return FIT_STATUS_OK;
}

/**
 *
 * \skip fit_licenf_consume_license
 *
 * This function is used to grant or deny access to different areas of functionality
 * in the software. This feature is similar to login type operation on licenses. It
 * will look for presence of feature id in the license binary.
 *
 * @param IN  \b  license       \n  Start address of the license in binary format,
 *                                  depending on your READ_LICENSE_BYTE definition
 *                                  e.g. in case of RAM, this can just be the memory
 *                                  address of the license variable 
 *
 * @param IN  \b  feature_id    \n  feature id which will be consumed/used for login
 *                                  operation.
 *
 * @param IN  \b  keys          \n  Pointer to array of key data. Also contains
 *                                  callback function to read key data in different
 *                                  types of memory(FLASH, E2, RAM).
 *
 * @return FIT_STATUS_FEATURE_EXPIRED if feature_if got expired
 * @return FIT_STATUS_INVALID_V2C if Invalid liocense binary data format.
 * @return FIT_STATUS_FEATURE_NOT_FOUND if feature id is not present in license binary.
 * @return FIT_STATUS_INVALID_LICENSE_TYPE if license type is not recognized.
 * @return FIT_STATUS_INACTIVE_LICENSE if license is not active yet.
 * @return FIT_STATUS_NO_CLOCK_SUPPORT if clock support is not present.
 * @return FIT_STATUS_INVALID_VALUE if Invalid value is found for license string passed in.
 * @return FIT_STATUS_RTC_NOT_PRESENT if real time clock is not present on hardware board
 * @return FIT_STATUS_INVALID_PARAM_1 if license string is NULL or not readable.
 * @return FIT_STATUS_INVALID_PARAM_2 if feature id is out of range.
 * @return FIT_STATUS_INVALID_PARAM_4 if rsa public key is NULL or not readable.
 *
 */
fit_status_t fit_licenf_consume_license(fit_pointer_t *license,
                                        uint32_t feature_id,
                                        fit_key_array_t *keys)
{
    uint8_t *lic_addr       = NULL;
    uint32_t curtime = 0;
    fit_pointer_t fitptr;
    fit_licensemodel_t licensemodel;
    fit_context_data_t context;
    fit_status_t status     = FIT_STATUS_UNKNOWN_ERROR;

    DBG(FIT_TRACE_INFO, "[fit_licenf_consume_license]: feature_id=%d, pdata=0x%p \n",
        feature_id, license->data);

    /* Validate parameters.*/
    if (license->read_byte == NULL)
        return FIT_STATUS_INVALID_PARAM_1;
    if (feature_id > FIT_MAX_FEATURE_ID_VALUE)
        return FIT_STATUS_INVALID_PARAM_2;
    if (keys->read_byte == NULL)
        return FIT_STATUS_INVALID_PARAM_4;

    fit_memset((uint8_t *)&context, 0 , sizeof(fit_context_data_t));
    fit_memset((uint8_t *)&licensemodel, 0, sizeof(fit_licensemodel_t));
    fit_memset((uint8_t *)&fitptr, 0, sizeof(fit_pointer_t));
    fitptr.read_byte = license->read_byte;

    /** Verify the license string against signing key data present in keys array
      * and node locking 
      */
    status = fit_verify_license(license, keys, FIT_TRUE);
    if (status != FIT_STATUS_OK)
        return status;

    DBG(FIT_TRACE_INFO, "See the presence of feature id ((%d) in license binary \n",
        feature_id );
    /* fill the requested operation type and its related data.*/
    context.operation = (uint8_t)FIT_OP_FIND_FEATURE_ID;
    context.parserdata.id = feature_id;
    context.status = FIT_STATUS_INVALID_VALUE;

    /*
     * Parse the license data to look for Feature id that will be used for
     * login type operation.
     */
    status = fit_parse_object(FIT_STRUCT_V2C_LEVEL, FIT_LICENSE_FIELD, license,
        &context);

    if (status == FIT_STATUS_OK && (context.parserstatus == FIT_INFO_STOP_PARSE ||
            context.parserstatus == FIT_INFO_CONTINUE_PARSE))
    {
        /* Set the consume license status value.*/
        status = (fit_status_t)context.status;
    }
    else
    {
        /*
         *If there is any error during lookup of feature ID then license string is
         * not valid.
         */
        return FIT_STATUS_INVALID_V2C;
    }

    if (status != FIT_INFO_FEATURE_ID_FOUND)
    {
        DBG(FIT_TRACE_ERROR, "Requested Feature ID NOT found error = %d\n", status);
        return FIT_STATUS_FEATURE_NOT_FOUND;
    }
    else
    {
        lic_addr = context.parserdata.addr;
        if (lic_addr == NULL)
            return FIT_STATUS_INVALID_V2C;
    }

    DBG(FIT_TRACE_INFO, "Requested Feature ID found with status = %d\n", status);

    fitptr.data = lic_addr;
    /* Get the license property data for feature ID found in license string.*/
    status = fit_get_lic_prop_data(&fitptr, &licensemodel);
    if (status != FIT_STATUS_OK)
        return FIT_STATUS_INVALID_VALUE;

    /* Get the current time in unixtime for time based licenses. */
    if (licensemodel.isstartdate == FIT_TRUE || licensemodel.isenddate == FIT_TRUE)
    {
        status = fit_getunixtime(&curtime);
        /* Return error if board does not support clock */
        if (status != FIT_STATUS_OK)
            return status;
    }

    /*
     * Start date can be present in license string even if license is perpetual one.
     * Validate start date against current time and some past time.
     */
    if (licensemodel.isstartdate == FIT_TRUE)
    {
        /*
         * Current time should be greater than some past time. Here 1449571095 
         * represent past time i.e. Dec 2015. Time interval on hardware boards
         * increments by 1 in unix time, so an valid current time would be
         * greater than some past time.
         */
        if (curtime <= 1449571095)
        {
            DBG(FIT_TRACE_ERROR, "No real time clock is present on board");
            return FIT_STATUS_RTC_NOT_PRESENT;
        }
        if (curtime < licensemodel.startdate)
            return FIT_STATUS_INACTIVE_LICENSE;
    }

    /*
     * Behavior of consume license is different for each type of license.
     * See if license is perpertual.
     */
    DBG(FIT_TRACE_INFO, "Check if license is perpetual one, is_perpetual=%d.\n",
        licensemodel.isperpetual);
    if (licensemodel.isperpetual == FIT_TRUE)
    {
        /*
         * For perpetual licenses, return status FIT_STATUS_OK if feature id is found
         * else return FIT_STATUS_FEATURE_NOT_FOUND.
         */
        DBG(FIT_TRACE_INFO, "Consume License operation completed succesfully.\n");
        return FIT_STATUS_OK;
    }
    /* Validate the expiration based license data */
    else if (licensemodel.isenddate == FIT_TRUE) /* If TRUE, means license is expiration based.*/
    {
        /* Validate expiration time agaist current time and start time(if present)
         * Current time should be greater than start date (time)
         */
        if (curtime < licensemodel.startdate)
            return FIT_STATUS_INACTIVE_LICENSE;

        if (licensemodel.enddate < curtime)
            return FIT_STATUS_FEATURE_EXPIRED;
        else
            return FIT_STATUS_OK;
    }

    return FIT_STATUS_INVALID_LICENSE_TYPE;
}
