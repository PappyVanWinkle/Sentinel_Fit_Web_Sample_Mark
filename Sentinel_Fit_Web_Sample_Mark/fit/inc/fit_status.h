/****************************************************************************\
**
** fit_status.h
**
** This file contains possible error codes used in Sentinel FIT.
** 
** Copyright (C) 2016, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#ifndef __FIT_STATUS_H__
#define __FIT_STATUS_H__

/* Required Includes ********************************************************/

/* Constants ****************************************************************/

/**
 * @defgroup fit_error_codes sentinel fit core Status Codes
 *
 * @{
 */

/**
 * because of MISRA rules we limit the defines to 32 characters
 *
 */
enum fit_error_codes
{
    /** Request successfully completed */
    FIT_STATUS_OK = 0,

    /** Sentinel FIT core is out of memory */
    FIT_STATUS_INSUFFICIENT_MEMORY,

    /** Specified Feature ID not available */
    FIT_STATUS_INVALID_FEATURE_ID,

    /** Invalid V2C/Binary data format */
    FIT_STATUS_INVALID_V2C,

    /** Access to Feature or functionality denied */
    FIT_STATUS_ACCESS_DENIED,

    /** Invalid value for Sentinel fit license string. */
    FIT_STATUS_INVALID_VALUE = 5,

    /** Unable to execute function in this context; the requested
     * functionality is not implemented */
    FIT_STATUS_REQ_NOT_SUPPORTED,

    /** Unknown algorithm used in V2C file */
    FIT_STATUS_UNKNOWN_ALGORITHM,

    /** signing key is not present in key array */
    FIT_STATUS_KEY_NOT_PRESENT,

    /** Requested Feature not available */
    FIT_STATUS_FEATURE_NOT_FOUND,

    /** Reserved status for future use */
    FIT_STATUS_RESERVED_2   = 10,

    /** Reserved status for future use */
    FIT_STATUS_RESERVED_3,

    /** Reserved status for future use */
    FIT_STATUS_RESERVED_4,

    /** licgen version used for generate license is not valid */
    FIT_STATUS_INVALID_LICGEN_VER,

    /** signature id is not valid */
    FIT_STATUS_INVALID_SIG_ID,

    /** Feature expired */
    FIT_STATUS_FEATURE_EXPIRED = 15,

    /** Error occurred during caching of sentinel fit licenses */
    FIT_STATUS_LIC_CACHING_ERROR,

    /** Invalid Product information */
    FIT_STATUS_INVALID_PRODUCT,

    /** Invalid function parameter */
    FIT_STATUS_INVALID_PARAM,

    /** Invalid function first parameter */
    FIT_STATUS_INVALID_PARAM_1,

    /** Invalid function second parameter */
    FIT_STATUS_INVALID_PARAM_2 = 20,

    /** Invalid function third parameter */
    FIT_STATUS_INVALID_PARAM_3,

    /** Invalid function fourth parameter */
    FIT_STATUS_INVALID_PARAM_4,

    /** Invalid function fifth parameter */
    FIT_STATUS_INVALID_PARAM_5,

    /** Reserved status for future use */
    FIT_STATUS_RESERVED_5,

    /** Reserved status for future use */
    FIT_STATUS_RESERVED_6   = 25,

    /** Invalid wire type */
    FIT_STATUS_INVALID_WIRE_TYPE,

    /** Internal error occurred in Sentinel fit core */
    FIT_STATUS_INTERNAL_ERROR,

    /** Invalid encryption key size */
    FIT_STATUS_INVALID_KEYSIZE,

    /** invalid vendor id */
    FIT_STATUS_INVALID_VENDOR_ID,

    /** invalid product id */
    FIT_STATUS_INVALID_PRODUCT_ID = 30,

    /** invalid license container id */
    FIT_STATUS_INVALID_CONTAINER_ID,

    /** Field data is present in license */
    FIT_STATUS_LIC_FIELD_PRESENT,

    /** Invalid license type */
    FIT_STATUS_INVALID_LICENSE_TYPE,

    /** Time expiration not supported */
    FIT_STATUS_LIC_EXP_NOT_SUPP,

    /** Invalid start date value */
    FIT_STATUS_INVALID_START_DATE = 35,

     /** Invalid end date value */
    FIT_STATUS_INVALID_END_DATE,

    /** License not active */
    FIT_STATUS_INACTIVE_LICENSE,

    /** No real time clock is present on board */
    FIT_STATUS_RTC_NOT_PRESENT,

    /** Clock support not present */
    FIT_STATUS_NO_CLOCK_SUPPORT,

    /** length not valid */
    FIT_STATUS_INVALID_FIELD_LEN = 40,

    /* Data comparison gets failed */
    FIT_STATUS_DATA_MISMATCH_ERROR,

    /* Code not compiled with node locking */
    FIT_STATUS_NODE_LOCKING_NOT_SUPP,

    /** fingerprint magic value not correct */
    FIT_STATUS_FP_MAGIC_NOT_VALID,

    /** Unknown fingerprint algorithm */
    FIT_STATUS_UNKNOWN_FP_ALGORITHM,

    /* Fingerprint data comparison gets failed */
    FIT_STATUS_FP_MISMATCH_ERROR = 45,

    /* Invalid device id length */
    FIT_STATUS_INVALID_DEVICE_ID_LEN,

    /** Signature verification operation failed */
    FIT_STATUS_INVALID_SIGNATURE,

    /** Unkwown error */
    FIT_STATUS_UNKNOWN_ERROR,

    /** RSA not supported */
    FIT_STATUS_NO_RSA_SUPPORT,

    /** AES not supported */
    FIT_STATUS_NO_AES_SUPPORT	= 50,

    /** Invalid key scope */
    FIT_STATUS_INVALID_KEY_SCOPE,

    /** Invalid RSA public key */
    FIT_STATUS_INVALID_RSA_PUBKEY,

};

/**
 * @}
 */

/* Types ********************************************************************/

typedef enum fit_error_codes fit_status_t;

/* Macro Functions **********************************************************/

#endif /* __FIT_STATUS_H__ */

