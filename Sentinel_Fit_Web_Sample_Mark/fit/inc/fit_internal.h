/****************************************************************************\
**
** fit_internal.h
**
** Contains declaration for strctures, enum, constants and functions used in Sentinel fit
** project and not exposed outside.
** 
** Copyright (C) 2016, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#ifndef __FIT_INTERNAL_H__
#define __FIT_INTERNAL_H__

/* Required Includes ********************************************************/

#if !defined(FIT_CONFIG_FILE)
#include "fit_config.h"
#else
#include FIT_CONFIG_FILE
#endif

#include <string.h>

#include "fit.h"

/* Constants ****************************************************************/

/** size of object pointer */
#define FIT_POBJECT_SIZE            sizeof(uint32_t)
/** size of array pointer */
#define FIT_PARRAY_SIZE             sizeof(uint32_t)
/** size of string pointer */
#define FIT_PSTRING_SIZE            sizeof(uint32_t)
/** size of field in sproto schema.*/
#define FIT_PFIELD_SIZE             sizeof(uint16_t)
/** Maximum no. of level supported in sproto schema */
#define FIT_MAX_LEVEL               0x10
/** Maximum no. of index in a level supported in sproto schema */
#define FIT_MAX_INDEX               0x10
/** RSA Signature length */
#define FIT_RSA_SIG_SIZE            0x100

/** fingerprint magic - 'fitF' */
#define FIT_FP_MAGIC                0x666D7446
/** Algorithm used for calculate hash for fingerprint data.*/
#define FIT_AES_FP_ALGID            0x1

/** Sentinel fit license schema data types.*/
enum fit_wire_type {
    /** Repesents integer data */
    FIT_INTEGER         = 1,
    /** Represents string data */
    FIT_STRING          = 2,
    /** Represents object.*/
    FIT_OBJECT          = 3,
    /** Represents arrays of object.*/
    FIT_ARRAY           = 4,

    FIT_INVALID_VALUE   = 0x0FF,
};

/** enum containing information codes used internally */
enum fit_information_codes
{
    /** Stop further parsing of Sentinel fit Licenses */
    FIT_INFO_STOP_PARSE               = 1,
    /** Continue parsing of Sentinel fit Licenses */
    FIT_INFO_CONTINUE_PARSE,
    /** Requested Feature found */
    FIT_INFO_FEATURE_ID_FOUND,
    /** Unit test failed error. */
    FIT_INFO_UNIT_TEST_FAILED,
    /** Unit test passes status. */
    FIT_INFO_UNIT_TEST_PASSED,
};

/*
 * Hard coded level and index values for sentinel fit licenses (as per sproto schema)
 * All fields will have unique index at each level. So all fields at level 0 will have
 * index value from 0..n, fields at level 1 will have index value from 0..n and so on.
 */
#define FIT_STRUCT_V2C_LEVEL                0
#define FIT_LICENSE_FIELD                   0
#define FIT_SIGNATURE_FIELD                 1

/** License data at level 1 */
#define FIT_STRUCT_LICENSE_LEVEL            1
#define FIT_HEADER_FIELD                    0
#define FIT_LICENSE_CONTAINER_FIELD         1
/** Signature data at level 1 */
#define FIT_STRUCT_SIGNATURE_LEVEL          1
#define FIT_ALGORITHM_ID_FIELD              2
#define FIT_SIGNATURE_DATA_FIELD            3

/** Header data at level 2 */
#define FIT_STRUCT_HEADER_LEVEL             2
#define FIT_LICGEN_VERSION_FIELD            0
#define FIT_LM_VERSION_FIELD                1
#define FIT_UID_FIELD                       2
#define FIT_FINGERPRINT_FIELD               3
/** License container data at level 2 */
#define FIT_STRUCT_LICENSE_CONTAINER_LEVEL  2
#define FIT_ID_LC_FIELD                     4
#define FIT_VENDOR_FIELD                    5

/** Vendor data at level 3 */
#define FIT_STRUCT_VENDOR_LEVEL             3
#define FIT_ID_VENDOR_FIELD                 0
#define FIT_PRODUCT_FIELD                   1
#define FIT_VENDOR_NAME_FIELD               2

/** Product information at level 4 */
#define FIT_STRUCT_PRODUCT_LEVEL            4
#define FIT_ID_PRODUCT_FIELD                0
#define FIT_VERSION_REGEX_FIELD             1
#define FIT_PRODUCT_PART_FIELD              2

/** Product part data at level 5 */
#define FIT_STRUCT_PRODUCT_PART_LEVEL       5
#define FIT_PRODUCT_PART_ID_FIELD           0
#define FIT_LIC_PROP_FIELD                  1

/** License property data at level 6 */
#define FIT_STRUCT_LIC_PROP_LEVEL           6
#define FIT_FEATURE_FIELD                   0
#define FIT_PERPETUAL_FIELD                 1
#define FIT_START_DATE_FIELD                2
#define FIT_END_DATE_FIELD                  3
#define FIT_COUNTER_FIELD                   4
#define FIT_DURATION_FROM_FIRST_USE_FIELD   5

/** Feature information at level 7 */
#define FIT_STRUCT_FEATURE_LEVEL            7
#define FIT_ID_FEATURE_FIELD                0

#define FIT_STRUCT_COUNTER_LEVEL            7
#define FIT_ID_COUNTER_FIELD                2
#define FIT_LIMIT_FIELD                     3
#define FIT_SOFT_LIMIT_FIELD                4
#define FIT_IS_FIELD                        5

/* Types ********************************************************************/

/** Type of licensing model supported.*/
typedef struct fit_licensemodel
{
    /** for perpetual licenses.*/
    fit_boolean_t   isperpetual;
    /** for time based licenses.*/
    fit_boolean_t   isstartdate;
    /** Start date information for time based licenses.*/
    uint32_t        startdate;
    /** for time expiration licenses.*/
    fit_boolean_t   isenddate;
    /** End date information for time based licenses.*/
    uint32_t        enddate;
} fit_licensemodel_t;

/*
 * Global structure for caching RSA validation data. It caches the hash of license
 * string using Davies Meyer hash function.
 */
typedef struct fit_cache_data {
    /** TRUE if RSA operation was performed, FALSE otherwise */
    fit_boolean_t rsa_check_done;
    /** Davies Meyer hash of license data.*/
    uint8_t dm_hash[FIT_DM_HASH_SIZE];
} fit_cache_data_t;

/*
 * Prototype of a callback function. This function is called during parsing of 
 * sentinel fit licenses.
 */
typedef fit_status_t (*fit_parse_callback)(fit_pointer_t *pdata,
                                           uint8_t level,
                                           uint8_t index,
                                           uint16_t length,
                                           void *context);

/*
 * This structure is used for registering fit_parse_callbacks for each operation type.
 * Each callback fn should have same prototype.
 */
typedef struct fit_parse_callbacks
{
    uint8_t operation;              /* Operation to be perform on license data */
    fit_parse_callback callback_fn; /* Callback function that will do operation */
} fit_callbacks_t;

#ifdef FIT_USE_UNIT_TESTS

/*
 * Prototype of a callback function. This function is called during parsing of sentinel fit
 * licenses for testing validity of licenses.
 */
typedef fit_status_t (*fit_test_field_callback)(fit_pointer_t *pdata,
                                                uint8_t level,
                                                uint8_t index,
                                                void *context);

/*
 * This structure is used for registering fit_parse_callbacks at particular level
 * and index. Callback function can be same at all levels and index or
 * different/unique for each level and index, but each callback fn should have same
 * prototype.
 */
struct fit_testcallbacks
{
    /** License schema level/depth info.*/
    uint8_t level;
    /** License schema index info.*/
    uint8_t index;
    /** Operation to be perform on license data */
    uint8_t operation;
    /** Callback function that will do operation */
    fit_test_field_callback callback_fn;
} fit_testcallbacks_t;

#endif /* #ifdef FIT_USE_UNIT_TESTS */

/* Function Prototypes ******************************************************/

/*
 * Callback function for get_info. Called for every item while traversing license data
 * This function will get complete license information for embedded devices
 */
fit_status_t fit_getlicensedata_cb (uint8_t tagid,
                                            fit_pointer_t *pdata,
                                            uint16_t length,
                                            fit_boolean_t *stop_parse,
                                            void *context);

/*
 * This function will fetch fingerprint/deviceid for the respective board. This will
 * call the hardware implemented callback function which will give raw data that would
 * be unique to each device. Raw data would be then hash with Daview Meyer hash function.
 */
fit_status_t fit_get_device_fpblob(fit_fingerprint_t* fp,
                                   fit_fp_callback callback_fn);

/** This function is used to validate the fingerprint information present in license data */
fit_status_t fit_validate_fp_data(fit_pointer_t *license);

/** This function will fetch licensing information present in the data passed in.*/
fit_status_t fit_testgetinfodata(fit_pointer_t *licenseData, uint8_t *pgetinfo,
                                 uint16_t *getinfolen);
/** This function will return the current time in unix.*/
fit_status_t fit_getunixtime(uint32_t *unixtime);

/** This function is used to validate signature (AES, RSA etc) in the license binary. */
fit_status_t fit_verify_license(fit_pointer_t *license,
                                fit_key_array_t *keys,
                                fit_boolean_t check_cache);

#ifdef FIT_USE_SYSTEM_CALLS
#define fit_memcpy memcpy
#define fit_memcmp memcmp
#define fit_memset memset
#else
void fit_memcpy(uint8_t *dst, uint8_t *src, uint16_t srclen);
int16_t fit_memcmp(uint8_t *pdata1, uint8_t *pdata2, uint16_t len);
void fit_memset(uint8_t *pdata, uint8_t value, uint16_t len);
#endif

void fitptr_memcpy(uint8_t *dst, fit_pointer_t *src);

#ifdef FIT_USE_NODE_LOCKING
void fit_get_fingerprint(fit_pointer_t *fpdata, fit_fingerprint_t *fpstruct);
#endif /* ifdef FIT_USE_NODE_LOCKING */


#endif  /* __FIT_INTERNAL_H__ */

