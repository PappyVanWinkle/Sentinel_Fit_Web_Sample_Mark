/****************************************************************************\
**
** fit_parser.c
**
** Defines functionality for parsing licenses for embedded devices.
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

#include <string.h> 

#include "fit_internal.h"
#include "fit_parser.h"
#include "fit_hwdep.h"
#include "fit_debug.h"
#include "fit_consume.h"
#include "fit_mem_read.h"
#include "fit_version.h"
#include "fit_aes.h"
#include "fit_rsa.h"
#include "fit_parse_arrays.h"

#ifdef FIT_USE_UNIT_TESTS
#include "unittest/fit_test_parser.h"
#endif /* #ifdef FIT_USE_UNIT_TESTS */

/* Forward Declarations *****************************************************/

/* This function will be used to get the field value at particular level and index.*/
static fit_status_t fit_parse_field_data(fit_pointer_t *pdata,
                                         uint8_t level,
                                         uint8_t index,
                                         uint16_t length,
                                         void *context);

/*
 * This function will be used to get address at particular level and index of
 * license binary.
 */
static fit_status_t fit_get_data_address(fit_pointer_t *pdata,
                                         uint8_t level,
                                         uint8_t index,
                                         uint16_t length,
                                         void *context);

/* Global Data **************************************************************/

/* This will contain data related to whether RSA verification is done or not.*/
fit_cache_data_t fit_cache = {FIT_FALSE, {0}};

/* Function Prototypes ******************************************************/

/*
 * This function will be called in case value of field is 00 00 and data is encoded
 * in data part.
 */
static fit_status_t fit_parse_data(uint8_t level,
                                   uint8_t index,
                                   fit_pointer_t *pdata,
                                   void *context);
/* This function will call the callback function register for each operation type.*/
static fit_status_t parsercallbacks(uint8_t level,
                                    uint8_t index,
                                    fit_pointer_t *pdata,
                                    uint16_t length,
                                    void *context);

#ifdef FIT_USE_UNIT_TESTS
static fit_status_t fieldcallbackfn(uint8_t level, uint8_t index, fit_pointer_t *pdata, void *context);
#endif /* #ifdef FIT_USE_UNIT_TESTS */

/* Constants ****************************************************************/
/* Callback function registered against each fit based operation.*/
struct fit_parse_callbacks fct[] = {{FIT_OP_FIND_FEATURE_ID, fit_find_feature_id},
                                    {FIT_OP_PARSE_LICENSE, fit_parse_field_data},
                                    {FIT_OP_GET_DATA_ADDRESS, fit_get_data_address}
#ifdef FIT_USE_UNIT_TESTS
              ,
                          {FIT_OP_GET_VENDORID, fit_get_vendor_id},
                          {FIT_OP_GET_LICENSE_UID, fit_get_license_uid}
#endif

};

#ifdef FIT_USE_UNIT_TESTS
/* Callback function registered against each level and index.*/
struct fit_testcallbacks testfct[] =
    {{FIT_STRUCT_LICENSE_LEVEL,
        FIT_LICENSE_CONTAINER_FIELD,
        FIT_OP_TEST_LIC_CONTAINER_DATA,
        fit_test_lic_container_data},

    {FIT_STRUCT_LICENSE_LEVEL,
        FIT_HEADER_FIELD,
        FIT_OP_TEST_LIC_HEADER_DATA,
        fit_test_header_data},

    {FIT_STRUCT_LICENSE_CONTAINER_LEVEL,
        FIT_VENDOR_FIELD,
        FIT_OP_TEST_VENDOR_DATA,
        fit_test_vendor_data},

    {FIT_STRUCT_VENDOR_LEVEL,
        FIT_PRODUCT_FIELD,
        FIT_OP_TEST_LIC_PRODUCT_DATA,
        fit_test_lic_product_data},

    {FIT_STRUCT_PRODUCT_LEVEL,
        FIT_PRODUCT_PART_FIELD,
        FIT_OP_TEST_LIC_PROPERTY_DATA,
        fit_test_lic_property_data},

    {FIT_STRUCT_LIC_PROP_LEVEL,
        FIT_FEATURE_FIELD,
        FIT_OP_TEST_FEATURE_DATA,
        fit_test_feature_info}};

#endif /* #ifdef FIT_USE_UNIT_TESTS */

/* Functions ****************************************************************/

/**
 *
 * fit_parse_object
 *
 * fit_parse_object will parse the license data passed to it. If data contains
 * the sub array or object then it calls appropriate routines/functions and passes
 * the address of corresponding array or object data.
 *
 * @param IN    level   \n level/depth of license schema to be parse by fit_parse_object
 *                         function.
 *
 * @param IN    index   \n Structure index. Each field will have unique index at each
 *                         level. So all fields at level 0 will have index value
 *                         from 0..n, fields at level 1 will have index value from
 *                         0..n and so on.
 *
 * @param IN    pdata   \n Pointer to fit_pointer_t structure containing license data.
 *                         To access the license data in different types of memory
 *                         (FLASH, E2, RAM), fit_pointer_t is used.
 *
 * @param IN    context \n Pointer to fit context structure.
 *
 * @return FIT_STATUS_OK on success otherwise, returns appropriate error code.
 * @return FIT_STATUS_INVALID_PARAM_3 if license string is not a valid one.
 *
 */
fit_status_t fit_parse_object(uint8_t level,
                              uint8_t index,
                              fit_pointer_t *pdata,
                              void *context)
{
    uint16_t cntr           = 0;
    /*
     * skip_fields represents number of fields to skip or number of fields that
     * does not have any data in license binary.
     */
    uint8_t skip_fields     = 0;
    uint8_t cur_index       = index;
    uint8_t *parserdata     = pdata->data;
    fit_pointer_t fitptr; 
    fit_context_data_t *pcontext  = (fit_context_data_t *)context;
    /* Header is a 16bit integer. It represents number of fields.*/
    uint16_t num_fields     = read_word(pdata->data, pdata->read_byte);
    /*
     * struct_offset contains value that represents start of field data(all except
     * integer data) i.e. number of bytes after which field data will start. If field
     * value is 00 00 that means data corresponding to that filed will be encoded in
     * data part.
     */
    uint16_t struct_offset  = (num_fields+1)*FIT_PFIELD_SIZE;
    /* Contains success or error code.*/
    fit_status_t status     = FIT_STATUS_OK;
    uint16_t field_data     = 0;

    DBG(FIT_TRACE_INFO, "[parse_object start]: for Level=%d, Index=%d, pdata=0x%X \n",
        level, index, pdata->data);

    fit_memset((uint8_t *)&fitptr, 0, sizeof(fit_pointer_t));
    fitptr.length = 0;
    fitptr.read_byte = pdata->read_byte;

    /*
     * First field represents no. of fields for object. Move data pointer to next
     * field to get first field data.
     */
    pdata->data = pdata->data + FIT_PFIELD_SIZE;

    /* Parse all fields data in a structure.*/
    for( cntr = 0; cntr < num_fields; cntr++)
    {
        /* If there is any error then stop further parsing and return the error.*/
        if (status != FIT_STATUS_OK)
            break;
        /*
         * Check parserstatus value in fit context data. If this is set to 
         * FIT_INFO_STOP_PARSE then stop further parsing of license string 
         */
        if (pcontext->parserstatus == FIT_INFO_STOP_PARSE)
            break;
        /*
         * Each field in field part is a 16bit integer  Value of this field will
         * tell what type of data it contains.
         */
        field_data = read_word(pdata->data, pdata->read_byte);
        /*
         * If field_data is zero, that means the field data is encoded in data part.
         * This field data can be in form of string or array or an object itself.
         */
        if( field_data == 0 )
        {
#ifdef FIT_USE_UNIT_TESTS
            /*
             * This code is used for unit tests. This will call the callback fn
             * registered for passed in level and index.
             */
            if (pcontext->testop == FIT_TRUE)
            {
                fitptr.data = parserdata+struct_offset;
                status = fieldcallbackfn(level, cur_index, &fitptr, context);
                /* If there is any error then stop further parsing and return the error.*/
                if (status != FIT_STATUS_OK)
                    break;
                /*
                 * Check parserstatus value in fit context data. If this is set to 
                 * FIT_INFO_STOP_PARSE or FIT_INFO_CONTINUE_PARSE then stop further
                 * operations.
                 */
                if (pcontext->parserstatus == FIT_INFO_STOP_PARSE ||
                        pcontext->parserstatus == FIT_INFO_CONTINUE_PARSE)
                    break;
            }
#endif /* #ifdef FIT_USE_UNIT_TESTS */

            /*
             * Get to data pointer where data corresponding to cur_index is present.
             * This data can be an array or an object or string or integer in form
             * of string. This will then call the appropriate functions based on
             * type of data.
             */
            fitptr.data = parserdata+struct_offset;

            status = fit_parse_data (level, cur_index, &fitptr, context);
            struct_offset   = (uint16_t)(struct_offset +
                (uint16_t)read_dword(parserdata+struct_offset, pdata->read_byte) +
                sizeof(uint32_t));
            /* Move data pointer to next field.*/
            pdata->data     = pdata->data + FIT_PFIELD_SIZE;
            /* Go to next index value.*/
            cur_index++;
        }

        /*
         * If value of field_data is odd, that means the tags is not continuous i.e.
         * we need to skip struct member fields by (field_data+1)/2 .
         */
        else if( field_data & 1)
        {
           skip_fields  = (uint8_t)(field_data+1)/2;
           /* Move data pointer to next field.*/
           pdata->data  = pdata->data + FIT_PFIELD_SIZE;
           /* skip the fields as it does not contain any data in V2C.*/
           cur_index    = cur_index + skip_fields;
        } 

        /*
         * if field_data is even (and not zero), then the field contains integer
         * value and the value of this field is field_data/2-1 
         */
        else if(field_data%2 == 0)
        {
#ifdef FIT_USE_UNIT_TESTS
            /*
             * This code is used for unit tests. This will call the callback fn
             * registered at particular level and index.
             */
            if (pcontext->testop == FIT_TRUE)
            {
                status = fieldcallbackfn(level, cur_index, pdata, context);
            }
            else
#endif /* #ifdef FIT_USE_UNIT_TESTS */

            /*
             * Get the value. Also if there is any callback function registered at
             * passed in level and index or operation requested by Fit context then
             * call the function.
             */
            status = parsercallbacks(level, cur_index, pdata, sizeof(uint16_t), context);

            /* Move data pointer to next field.*/
            pdata->data = pdata->data + FIT_PFIELD_SIZE;
            /* Go to next index value.*/
            cur_index++;
        }
        else
        {
            /* Wrong data.*/
            DBG(FIT_TRACE_CRITICAL, "[parse_object]: Invalid license data. \n");
            status = FIT_STATUS_INVALID_PARAM_3;
            break;
        }
    }

    /* Length of the license binary data passed in.*/
    pcontext->length = struct_offset;
    /* Get license property address corresponding to feature id found.*/
    if(pcontext->operation == FIT_OP_FIND_FEATURE_ID &&
        pcontext->status == FIT_INFO_FEATURE_ID_FOUND &&
        level == FIT_STRUCT_LIC_PROP_LEVEL && index == FIT_FEATURE_FIELD)
    {
        pcontext->parserdata.addr = parserdata;
    }

    DBG(FIT_TRACE_INFO, "[parse_object end]: for Level=%d, Index=%d \n\n", level, index);
    pdata->data = parserdata;
    return status;
}

/**
 *
 * fit_parse_data
 *
 * This function will be called in case value of field is 00 00 and data is encoded
 * in data part. Passed data can be in form of Array, object, string or integer(in form of string)
 * Calls the appropriate routines/functions based on type of data and passes the
 * corresponding data pointer.
 *
 * @param IN    level   \n level/depth of license schema to be parse by fit_parse_data
 *                         function.
 *
 * @param IN    index   \n Structure index. Each field will have unique index at each
 *                         level. So all fields at level 0 will have index value
 *                         from 0..n, fields at level 1 will have index value from
 *                         0..n and so on.
 *
 * @param IN    pdata   \n Pointer to fit_pointer_t structure containing license data.
 *                         To access the license data in different types of memory
 *                         (FLASH, E2, RAM), fit_pointer_t is used.
 *
 * @param IN    context \n Pointer to fit context structure.
 *
 */
static fit_status_t fit_parse_data(uint8_t level,
                                   uint8_t index,
                                   fit_pointer_t *pdata,
                                   void *context)
{
    uint8_t startindex  = 0;
    fit_status_t status = FIT_STATUS_OK;
    fit_pointer_t fitptr; 
    /* Get the field type corresponding to level and index.*/
    wire_type_t type    = get_field_type(level, index);
    fit_context_data_t *pcontext  = (fit_context_data_t *)context;

    DBG(FIT_TRACE_INFO, "[parse_data start]: for Level=%d, Index=%d, Type=%d \n",
        level, index, type);

    fit_memset((uint8_t *)&fitptr, 0, sizeof(fit_pointer_t));
    fitptr.length = 0;
    fitptr.read_byte = pdata->read_byte;

    switch(type)
    {
        case(FIT_ARRAY):
        {
            /*
             * Check if there is any operation or some checks that need to be
             * performed on object.
             */
            status = parsercallbacks(level, index, pdata, FIT_POBJECT_SIZE, context);
            if (status != FIT_STATUS_OK)
                break;

            /* Field value in data part represents an array.*/
            status = fit_parse_array(level+1, startindex, pdata, context);
            if (status != FIT_STATUS_OK)
                break;
        }
        break;

        case (FIT_OBJECT):
        {
            /*
             * Check if there is any operation or some checks that need to be 
             * performed on object.
             */
            status = parsercallbacks(level, index, pdata, FIT_POBJECT_SIZE, context);
            if (status != FIT_STATUS_OK)
                break;

            /* Field value in data part represents an object.*/
            fitptr.data = pdata->data+FIT_POBJECT_SIZE;
            status = fit_parse_object(level+1, startindex, &fitptr, context);
            if (status != FIT_STATUS_OK)
                break;
        }
        break;

        case (FIT_STRING):
        case (FIT_INTEGER):
        {
#ifdef FIT_USE_UNIT_TESTS
            /*
             * This code is used for unit tests. This will call the callback fn
             * registered at particular level and index.
             */
            if (((fit_context_data_t *)context)->testop == FIT_TRUE)
            {
                fitptr.data = pdata->data+FIT_PSTRING_SIZE;
                status = fieldcallbackfn(level, index, &fitptr, context);
            }
            else
            {
#endif /* #ifdef FIT_USE_UNIT_TESTS */
                /*
                 * Field value in data part contains string value or integer value in
                 * form of string like vendor id = "37515"
                 */
                fitptr.data = pdata->data+FIT_PSTRING_SIZE;
                status = parsercallbacks(level, index, &fitptr,
                    (uint16_t)read_dword(pdata->data, pdata->read_byte), context);
#ifdef FIT_USE_UNIT_TESTS
            }
#endif /* #ifdef FIT_USE_UNIT_TESTS */

            /* If there is any error then stop further parsing and return the error.*/
            if (status != FIT_STATUS_OK)
                break;
            /*
             * Check parserstatus value in fit context data. If this is set to 
             * FIT_INFO_STOP_PARSE then stop further parsing of license string 
             */
            if (pcontext->parserstatus == FIT_INFO_STOP_PARSE)
                break;
        }
        break;

        default:
        {
            DBG(FIT_TRACE_CRITICAL, "[parse_data]: Invalid wire type \n");
            /* Invalid wire type or not supported.*/
            status = FIT_STATUS_INVALID_WIRE_TYPE;
        }
            break;
    }

    DBG(FIT_TRACE_INFO, "[parse_data end]: for Level=%d, Index=%d\n", level, index);
    return status;
}

/**
 *
 * fit_parse_array
 *
 * License string can have array of data like array of features in one product
 * or array of products per vendor. fit_parse_array function will traverse each
 * object of an array and call appropriate functions to parse individual objects
 * of an array.
 *
 * @param IN    level   \n level/depth of license schema to be parse by fit_parse_array
 *                         function.
 *
 * @param IN    index   \n Structure index. Each field will have unique index at each
 *                         level. So all fields at level 0 will have index value
 *                         from 0..n, fields at level 1 will have index value from
 *                         0..n and so on.
 *
 * @param IN    pdata   \n Pointer to fit_pointer_t structure containing license data.
 *                         To access the license data in different types of memory
 *                         (FLASH, E2, RAM), fit_pointer_t is used.
 *
 * @param IN    context \n Pointer to fit context structure.
 *
 *
 */
fit_status_t fit_parse_array(uint8_t level, uint8_t index, fit_pointer_t *pdata, void *context)
{
    /* Get the total size of array in bytes.*/
    uint32_t arraysize  = read_dword(pdata->data, pdata->read_byte);
    /* Get the size of first structure in that array.*/
    uint8_t *dataoffset = pdata->data + FIT_PARRAY_SIZE;
    uint16_t cntr       = 0;
    fit_pointer_t fitptr; 
    /* contains success or error code.*/
    fit_status_t status = FIT_STATUS_OK;

    fit_memset((uint8_t *)&fitptr, 0, sizeof(fit_pointer_t));
    fitptr.length = 0;
    fitptr.read_byte = pdata->read_byte;

    for(cntr = 0; cntr < arraysize;)
    {
        /*
         * Call the fit_parse_object function that will parse the structure component
         * of the array. (dataoffset+FIT_POBJECT_SIZE) will contain the size of each
         * structure in array.
         */
        fitptr.data = dataoffset+FIT_POBJECT_SIZE;

        status = fit_parse_object(level, index, &fitptr, context);
        if (status != FIT_STATUS_OK)
            break;
        cntr += (uint16_t)(FIT_POBJECT_SIZE + read_dword(dataoffset, pdata->read_byte));
        /* Get to the next structure data in the array.*/
        dataoffset += FIT_POBJECT_SIZE + read_dword(dataoffset, pdata->read_byte);
    }

    return status;
}

/**
 *
 * get_field_type
 *
 * Return wire type corresponding to index and level passed in.
 *
 * @param IN    level   \n level/depth of license schema to be parsed.
 *
 * @param IN    index   \n Structure index. Each field will have unique index at each
 *                         level. So all fields at level 0 will have index value
 *                         from 0..n, fields at level 1 will have index value from
 *                         0..n and so on.
 *
 */
wire_type_t get_field_type(uint8_t level, uint8_t index)
{
    /* Validate Parameters.*/
    if (level >= FIT_MAX_LEVEL)
        return FIT_INVALID_VALUE;
    if (index >= FIT_MAX_INDEX)
        return FIT_INVALID_VALUE;

    /* Field type is hard-coded based on level and Index of the structure in question */
#ifdef __AVR__
    return pgm_read_byte((uint16_t)lic_field_type + (level*FIT_MAX_INDEX) + index);
#else
    return lic_field_type[level][index];
#endif
}

/**
 *
 * get_tag_id
 *
 * Return tag id corresponding to index and level passed in.
 *
 * @param IN    level   \n level/depth of license schema to be parsed.
 *
 * @param IN    index   \n Structure index. Each field will have unique index at each
 *                         level. So all fields at level 0 will have index value
 *                         from 0..n, fields at level 1 will have index value from
 *                         0..n and so on.
 *
 */
static uint8_t get_tag_id(uint8_t level, uint8_t index)
{
    /* Validate Parameters.*/
    if (level >= FIT_MAX_LEVEL)
        return FIT_INVALID_VALUE;
    if (index >= FIT_MAX_INDEX)
        return FIT_INVALID_VALUE;

    /* tag id is hard-coded based on level and Index of the structure in question */
#ifdef __AVR__
    return pgm_read_byte((uint16_t)lic_tag_id + (level*FIT_MAX_INDEX) + index);
#else
    return lic_tag_id[level][index];
#endif
}

/**
 *
 * fit_parse_field_data
 *
 * This function will be used to parse/get the field value present in license binary
 * at given level and index.
 *
 * @param IN    pdata   \n Pointer to fit_pointer_t structure containing license
 *                         data at a given level and index.
 *
 * @param IN    level   \n level/depth of license schema.
 *
 * @param IN    index   \n structure index whose value is to be fetched.
 *
 * @param IN    length  \n Length of the data to be get.
 *
 * @param IN    context \n Pointer to fit context structure.
 *
 */
fit_status_t fit_parse_field_data(fit_pointer_t *pdata,
                                    uint8_t level,
                                    uint8_t index,
                                    uint16_t length,
                                    void *context)
{
    uint32_t integer        = 0;
    uint8_t string[64];
    fit_pointer_t fitptr; 
    /* Get the field type corresponding to level and index.*/
    wire_type_t type        = get_field_type(level, index);
    fit_context_data_t *pcontext = (fit_context_data_t *)context;

    DBG(FIT_TRACE_INFO, "[fit_parse_field_data]: for Level=%d, Index=%d, length=%d bytes,"
        " type=%d, pdata=0x%X \n", level, index, length, type, pdata->data);

    fit_memset((uint8_t *)&fitptr, 0, sizeof(fit_pointer_t));
    fit_memset(string, 0, sizeof(string));
    fitptr.read_byte = pdata->read_byte;

    /*
     * Field type should be either FIT_INTEGER or FIT_STRING; otherwise continue
     *  with license parsing.
     */
    if (!(type == (uint8_t)FIT_INTEGER || type == (uint8_t)FIT_STRING))
    {
        pcontext->parserstatus = FIT_INFO_CONTINUE_PARSE;
        return FIT_STATUS_OK;
    }
    /* Check if field length is greater than maximum allowed.*/
    if (level != FIT_STRUCT_SIGNATURE_LEVEL && index != FIT_SIGNATURE_DATA_FIELD)
        if (length > FIT_MAX_FIELD_SIZE)
            return FIT_STATUS_INVALID_FIELD_LEN;

    /* Get integer value. Integer value can be 16 bit value or 32 bit value.*/
    if (type == (uint8_t)FIT_INTEGER)
    {
        /* Get the 16 bit field value.*/
        if (length == sizeof(uint16_t))
        {
            integer = (read_word(pdata->data, pdata->read_byte)/2)-1;
            DBG(FIT_TRACE_INFO, "Integer Value = %ld\n", integer);
        }
        /* Get the 32 bit field value.*/
        else if (length == sizeof(uint32_t))
        {
            /* This represents integer data in form of string, so need to do calculations.*/
            integer = read_dword(pdata->data, pdata->read_byte);
            DBG(FIT_TRACE_INFO, "Integer Value = %ld\n", integer);
        }
    }
    else if (type == (uint8_t)FIT_STRING) /* Get string value.*/
    {
        if (level != FIT_STRUCT_SIGNATURE_LEVEL && index != FIT_SIGNATURE_DATA_FIELD)
        {
            /* Get the string value.*/
            if (length < sizeof(string))
            {
                fitptr.data = pdata->data;
                fitptr.length = length;
                fitptr_memcpy(string, &fitptr);
                DBG(FIT_TRACE_INFO, "String Data [length=%d] =\"%X\" \n", length, string);
            }
            else
            {
                DBG(FIT_TRACE_CRITICAL, "[fit_parse_field_data]: Requested string data "
                    "is of longer size.\n");
                return FIT_STATUS_INSUFFICIENT_MEMORY;
            }
        }
    }

    /* Validate RSA signature length. For Sentinel Fit length should be equal to
     * FIT_RSA_SIG_SIZE 
     */
    if (level == FIT_STRUCT_SIGNATURE_LEVEL && index == FIT_SIGNATURE_DATA_FIELD)
    {
        if (!(length == FIT_RSA_SIG_SIZE || length == FIT_AES_128_KEY_LENGTH))
            return FIT_STATUS_INVALID_FIELD_LEN;
    }

    /* Validate license generation value. For Sentinel Fit should be >= FIT_INITIAL_VERSION */
    else if (level == FIT_STRUCT_HEADER_LEVEL && index == FIT_LICGEN_VERSION_FIELD)
    {
        if (integer < FIT_INITIAL_VERSION )
            return FIT_STATUS_INVALID_LICGEN_VER;
    }
    /* Validate Algorithm used for signing license data.*/
    else if (level == FIT_STRUCT_SIGNATURE_LEVEL && index == FIT_ALGORITHM_ID_FIELD)
    {
        if (!(integer >= FIT_RSA_2048_ADM_PKCS_V15_ALG_ID || integer <= FIT_AES_128_OMAC_ALG_ID))
            return FIT_STATUS_INVALID_SIG_ID;
    }
    /* Validate vendor ID.*/
    else if (level == FIT_STRUCT_LICENSE_CONTAINER_LEVEL && index == FIT_VENDOR_FIELD)
    {
        if (integer > FIT_MAX_VENDOR_ID_VALUE)
            return FIT_STATUS_INVALID_VENDOR_ID;
    }
    /*
     * If fingerprint is present then fit core should compiled with FIT_USE_NODE_LOCKING
     * macro. If not return error.
     */
    else if ((level == FIT_STRUCT_HEADER_LEVEL && index == FIT_FINGERPRINT_FIELD))
    {
#ifndef FIT_USE_NODE_LOCKING
            return FIT_STATUS_NODE_LOCKING_NOT_SUPP;
#endif
    }
    /* Validate license container ID.*/
    else if (level == FIT_STRUCT_LICENSE_CONTAINER_LEVEL && index == FIT_ID_LC_FIELD)
    {
        if (integer > FIT_MAX_LC_ID_VALUE)
            return FIT_STATUS_INVALID_CONTAINER_ID;
    }
    /* Validate product ID value.*/
    else if (level == FIT_STRUCT_PRODUCT_LEVEL && index == FIT_ID_PRODUCT_FIELD)
    {
        if (integer > FIT_MAX_PRODUCT_ID_VALUE)
            return FIT_STATUS_INVALID_PRODUCT_ID;
    }
    /* Validate Feature ID value.*/
    else if (level == FIT_STRUCT_FEATURE_LEVEL && index == FIT_ID_FEATURE_FIELD)
    {
        if (integer > FIT_MAX_FEATURE_ID_VALUE)
            return FIT_STATUS_INVALID_FEATURE_ID;
    }
    /* Validate start date */
    else if (level == FIT_STRUCT_LIC_PROP_LEVEL && index == FIT_START_DATE_FIELD)
    {
        if (!(integer > 0 && integer <= FIT_MAX_START_DATE_VALUE))
            return FIT_STATUS_INVALID_START_DATE;
    }
    /* Validate end date.*/
    else if (level == FIT_STRUCT_LIC_PROP_LEVEL && index == FIT_END_DATE_FIELD)
    {
        if (!(integer > 0 && integer <= FIT_MAX_END_DATE_VALUE))
            return FIT_STATUS_INVALID_END_DATE;
    }

    DBG(FIT_TRACE_INFO, "\n");

    return FIT_STATUS_OK;
}

/**
 *
 * fit_get_data_address
 *
 * This function will be used to get address at particular level and index of
 * license binary.
 *
 * @param IN    pdata   \n Pointer to fit_pointer_t structure containing license
 *                         data at a given level and index.
 *
 * @param IN    level   \n level/depth of license schema.
 *
 * @param IN    index   \n structure index whose value is to be fetched.
 *
 * @param IN    length  \n Length of the data to be get.
 *
 * @param IN    context \n Pointer to fit context structure.
 *
 */
fit_status_t fit_get_data_address(fit_pointer_t *pdata,
                                    uint8_t level,
                                    uint8_t index,
                                    uint16_t length,
                                    void *context)
{
    fit_context_data_t *pcontext  = (fit_context_data_t *)context;
    fit_status_t status         = FIT_STATUS_OK;

    if (level == pcontext->level && index == pcontext->index)
    {
        DBG(FIT_TRACE_INFO, "[fit_get_data_address]: for Level=%d, Index=%d, pdata=0x%X \n",
            level, index, pdata->data);

        pcontext->parserdata.addr = (uint8_t *)pdata->data;
        pcontext->parserstatus = FIT_INFO_STOP_PARSE;
        pcontext->status = FIT_STATUS_LIC_FIELD_PRESENT;
    }

    return status;
}

#ifdef FIT_USE_UNIT_TESTS

/**
 *
 * fieldcallbackfn
 *
 * This function will call the callback function register at particular level and
 * index of the license schema.
 *
 * @param IN    level   \n level/depth of license schema.
 *
 * @param IN    index   \n Structure index. Each field will have unique index at each
 *                         level. So all fields at level 0 will have index value
 *                         from 0..n, fields at level 1 will have index value from
 *                         0..n and so on.
 *
 * @param IN    pdata   \n Pointer to fit_pointer_t structure containing license data
 *                         at a given level and index.
 *
 * @param IN    context \n Pointer to fit context structure.
 *
 */
fit_status_t fieldcallbackfn(uint8_t level,
                             uint8_t index,
                             fit_pointer_t *pdata,
                             void *context)
{
    fit_context_data_t *pcontext  = (fit_context_data_t *)context;
    uint16_t cntr               = 0;
    fit_status_t status         = FIT_STATUS_OK;
    
    /* Get the field type corresponding to level and index.*/
    if (level >= FIT_MAX_LEVEL)
        return FIT_STATUS_INVALID_PARAM_1;
    if (index >= FIT_MAX_INDEX)
        return FIT_STATUS_INVALID_PARAM_2;

    DBG(FIT_TRACE_INFO, "[fieldcallbackfn start]: for Level=%d, Index=%d, pdata=0x%X \n",
        level, index, pdata->data);

    /* Call callback function that is registered against passed in level and index.*/
    for(cntr = 0; cntr < (sizeof(testfct)/sizeof(struct fit_testcallbacks)); cntr++)
    {
        if( (testfct[cntr].level == pcontext->level && testfct[cntr].index == pcontext->index) &&
            (testfct[cntr].level == level && testfct[cntr].index == index))
        {
            status = testfct[cntr].callback_fn(pdata, pcontext->level, pcontext->index, context);
            break;
        }
    }

    return status;
}
#endif /* #ifdef FIT_USE_UNIT_TESTS */

/**
 *
 * parsercallbacks
 *
 * This function will call the callback function register for each operation type.
 *
 * @param IN    level   \n level/depth of license schema.
 *
 * @param IN    index   \n structure index.
 *
 * @param IN    pdata   \n Pointer to fit_pointer_t structure containing license
 *                         data at a given level and index.
 *
 * @param IN    length  \n Length of the data to be get.
 *
 * @param IN    context \n Pointer to fit context structure.
 *
 */
fit_status_t parsercallbacks(uint8_t level,
                             uint8_t index,
                             fit_pointer_t *pdata,
                             uint16_t length,
                             void *context)
{
    fit_context_data_t *pcontext  = (fit_context_data_t *)NULL;
    uint16_t cntr               = 0;
    fit_status_t status         = FIT_STATUS_OK;
    fit_boolean_t stop_parse           = FIT_FALSE;

    /* Validate parameters passed in.*/
    if (level >= FIT_MAX_LEVEL)
        return FIT_STATUS_INVALID_PARAM_1;
    if (index >= FIT_MAX_INDEX)
        return FIT_STATUS_INVALID_PARAM_2;
    if (pdata == NULL)
        return FIT_STATUS_INVALID_PARAM_3;
    if (context == NULL)
        return FIT_STATUS_INVALID_PARAM_5;

    DBG(FIT_TRACE_INFO, "[parsercallbacks start]: for Level=%d, Index=%d, pdata=0x%X \n",
        level, index, pdata->data);

    pcontext = (fit_context_data_t *)context;
    if (pcontext->operation > FIT_OP_LAST)
        return FIT_STATUS_INVALID_PARAM_5;
    if (pcontext->operation == FIT_OP_NONE)
        return FIT_STATUS_OK;

    /*
     * Call the getinfo api fn for each level and index if operation requested
     * is FIT_OP_GET_LICENSE_INFO_DATA
     */
    if (pcontext->operation == (uint8_t)FIT_OP_GET_LICENSE_INFO_DATA)
    {
        /* Get the tagid corresponding to level and index.*/
        uint8_t tagid = get_tag_id(level, index);
        fit_v2c_data_t *v2c = (fit_v2c_data_t *)pcontext->parserdata.getinfodata.get_info_data;

        DBG(FIT_TRACE_INFO, "Calling user provided callback function\n");
        status = pcontext->parserdata.getinfodata.callback_fn(tagid, pdata, length, &stop_parse, v2c);
        if (stop_parse == FIT_TRUE)
            pcontext->parserstatus = FIT_INFO_STOP_PARSE;
    }
    /* Else Call the callback function that is registered against operation type.*/
    else
    {
        for(cntr = 0; cntr < (sizeof(fct)/sizeof(struct fit_parse_callbacks)); cntr++)
        {
            if( fct[cntr].operation == pcontext->operation )
            {
                status = fct[cntr].callback_fn(pdata, level, index, length, pcontext);
                break;
            }
        }
    }

    DBG(FIT_TRACE_INFO, "[parsercallbacks end]: for Level=%d, Index=%d \n", level, index);
    return status;
}
