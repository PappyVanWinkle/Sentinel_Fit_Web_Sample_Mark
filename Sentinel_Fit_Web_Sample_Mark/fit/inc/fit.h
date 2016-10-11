/****************************************************************************\
**
** fit.h
**
** Sentinel FIT Licensing interface header file. File contains exposed interface for
** C/C++ language.
** 
** Copyright (C) 2016, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#ifndef __FIT_H__
#define __FIT_H__

/* Required Includes ********************************************************/
#include "fit_types.h"
#include "fit_api.h"

/* Constants ****************************************************************/

//@@@axel
#define FIT_RSA_SIG_SIZE            0x100


/** Maximum feature id value supported */
#define FIT_MAX_FEATURE_ID_VALUE        0xFFFFFFFF
/** Maximum product id value supported */
#define FIT_MAX_PRODUCT_ID_VALUE        0xFFBF
/** Maximum container id value supported */
#define FIT_MAX_LC_ID_VALUE             0xFFFFFFFF
/** Maximum vendor id value supported */
#define FIT_MAX_VENDOR_ID_VALUE         0xFFFFFF
/** Maximum value for start date (unix time) */
#define FIT_MAX_START_DATE_VALUE        0x7FFFFFFF
/** Maximum value for end date (unix time) */
#define FIT_MAX_END_DATE_VALUE          0x7FFFFFFF
/** Maximum UID length */
#define FIT_UID_LEN                     0x20
/** Maximum length for any field in sproto (except RSA signature) */
#define FIT_MAX_FIELD_SIZE              0x20
/** Davies meyer hash size */
#define FIT_DM_HASH_SIZE                0x10
/** Version Regex length*/
#define FIT_VER_REGEX_LEN               0x20

enum fit_license_type {
    /** Invalid value */
    FIT_LIC_INVALID_VALUE       = 0,
    /** Perpetual licenses */
    FIT_LIC_PERPETUAL,
    /** Time based licenses i.e no. of days from its first use */
    FIT_LIC_TIME_BASED,
    /** Execution based licenses */
    FIT_LIC_COUNTER_BASED,
    /** Time expiration based licenses */
    FIT_LIC_EXPIRATION_BASED,
};

/** Enum describing types of query to be operate on sentinel fit licenses. */
enum fit_operation_type {
    /** Default value. It means no data requested */
    FIT_OP_NONE              = 0,
    /** Parse sentinel fit license */
    FIT_OP_PARSE_LICENSE,
    /** consume one license at each consume license apil call. */
    FIT_OP_FIND_FEATURE_ID,
    /** get the field data at particular level and index */
    FIT_OP_GET_FIELD_DATA,
    /** Get vendor information */
    FIT_OP_GET_VENDORID,
    /** Get license UID value */
    FIT_OP_GET_LICENSE_UID,
    /** Get data address at particular level and index */
    FIT_OP_GET_DATA_ADDRESS,
    /** Get licence related info */
    FIT_OP_GET_LICENSE_INFO_DATA,

#ifdef FIT_USE_UNIT_TESTS
    /*
     * Describes types of query to be operate on sentinel fit licenses for testing
     *licence string.
     */

    /** test for validate license data i.e. it should parse without any error.*/
    FIT_OP_TEST_PARSE_LICENSE,
    /** test for validate license container data */
    FIT_OP_TEST_LIC_CONTAINER_DATA,
    /** test for validate license vendor information data like vendor id etc. */
    FIT_OP_TEST_VENDOR_DATA,
    /** test for validate license product definition. */
    FIT_OP_TEST_LIC_PRODUCT_DATA,
    /** test for validate license property information. */
    FIT_OP_TEST_LIC_PROPERTY_DATA,
    /** test for validate license fetaure definition or data. */
    FIT_OP_TEST_FEATURE_DATA,
    /** test for validate license header information like version information etc. */
    FIT_OP_TEST_LIC_HEADER_DATA,
    /** test for parsing license strung from any level and index. */
    FIT_OP_TEST_PARSE_FROM_ANY_LEVEL,
    /** test for wire protocol */
    FIT_OP_TEST_WIRE_PROTOCOL,
    /** test for validity of AES algorithm */
    FIT_OP_TEST_AES_ALGORITHM,
#endif /* #ifdef FIT_USE_UNIT_TESTS */

    FIT_OP_LAST,
};


/* Forward Declarations *****************************************************/

/* Types ********************************************************************/

/*
 * Defines context data for sentinel fit. This structure is used when user wants to query
 * license data, or wants to see current state of sentinel fit licenses.
 */
typedef struct fit_context {
    /*
     * Defines operation type to be performed on license string. See enum 
     * fit_operation_type
     */
    uint8_t operation;
    /** License schema level/depth info.*/
    uint8_t level;
    /** License schema index info. Each field will have unique index at each level.*/
    uint8_t index;
    /** FIT_TRUE if test callback fn to be called; FIT_FALSE otherwise.*/
    fit_boolean_t testop;
    /** Contains length of license data.*/
    uint16_t length;
    /** Contains Return value if required.*/
    uint8_t status;
    /** Contains information code value like FIT_INFO_STOP_PARSE, FIT_INFO_CONTINUE_PARSE etc. */
    uint8_t parserstatus;

    union {
        /*
         * License data address. To be used for getting pointer to license data at
         * particular level and index.
         */
        uint8_t *addr;
        /*
        * Can be feature id or product id or any other valid value for sentinel fit
        * based licenses.
        */
        uint32_t id;
        /** Query for vendor id.*/
        uint32_t vendorid;
        /** Contains license unique UID value.*/
        uint8_t uid[FIT_UID_LEN];

        /** get info data.*/
        struct {
            /** Pointer to callback function to be called for get info api.*/
            fit_get_info_callback callback_fn;
            /** Pointer to requested data for get info api.*/
            void *get_info_data;
        } getinfodata;

    } parserdata;

} fit_context_data_t;

/** Structure describing fingerprint information.*/
typedef struct fit_fingerprint {
/** fingerprint magic.*/
    uint32_t    magic;
/*
 * fingerprint algorithm id - to spare space alg_id size 
 * differs than one from licgen which is uint32_t
 */
    uint8_t     algid;
/** hash (Davies Meyer) of fingerprint */
    uint8_t     hash[FIT_DM_HASH_SIZE];
} fit_fingerprint_t;

/* Structure defining license features information */
typedef struct fit_feature {
    /** feature ID */
    uint32_t featid;
    /** Pointer to next feature ID (one product ID can contain multiple features) */
    struct fit_feature *next;
} fit_feature_data_t;

/*
 * Structure defining product license property information. All features inside
 * product share same licensing model.
 */
typedef struct fit_property {
    /** Pointer to feature data.*/
    fit_feature_data_t  *feat;
    /** Start date information for time based licenses.*/
    uint32_t        startdate;
    /** End date information for time based licenses.*/
    uint32_t        enddate;
    /** tell whether feature's are perpetual or not.*/
    uint8_t         perpetual;
} fit_property_data_t;

/** Structure defining product part information for multi license model.*/
typedef struct fit_prodpart {
    /** Product Part ID.*/
    uint32_t        partid;
    /** Structure containing license property information.*/
    fit_property_data_t properties;
    /** License type */
    uint8_t         lictype;
    /** Pointer to next product part information.*/
    struct fit_prodpart *next;
} fit_prodpart_data_t;

/** Structure defining license product information.*/
typedef struct fit_product {
    /** Product ID.*/
    uint32_t        prodid;
    /** Product version related information.*/
    char            verregex[FIT_VER_REGEX_LEN];
    /** Pointer to product part information.*/
    fit_prodpart_data_t *prodpart;
} fit_product_data_t;

/** Structure defining vendor information.*/
typedef struct fit_vendor {
    /** Vendor ID.*/
    uint32_t        vendorid;
    /** Pointer to license product information.*/
    fit_product_data_t  prod;
} fit_vendor_data_t;

/** Structure defining license Container information.*/
typedef struct fit_container {
    /** License container ID.*/
    uint32_t        id;
    /** Pointer to Vendor information.*/
    fit_vendor_data_t   *vendor;
} fit_container_data_t;

/** Structure defining License Header information.*/
typedef struct fit_header {
    /** Licgen version used for creating licenses for embedded devices.*/
    uint16_t    licgen_version;
    /** LM version used.*/
    uint16_t    lm_version;
    /** Unique license identifier. Used in creating license updates.*/
    uint8_t     uid[FIT_UID_LEN];
    /** fingerprint data.*/
    fit_fingerprint_t licensefp;
} fit_header_data_t;

/** Structure defining license data for embedded devices.*/
typedef struct fit_license {
    /** Structure defining License Header data.*/
    fit_header_data_t       header;
    /** Pointer to license container data.*/
    fit_container_data_t    *cont;
} fit_license_data_t;

/** Structure defining license signature data.*/
typedef struct fit_signature {
    /** Algorithm used for signing license data for embedded devices.*/
    uint16_t    algid;
} fit_signature_data_t;

/** Structure defining V2C data.*/
typedef struct fit_v2c {
    /** Structure containing license data.*/
    fit_license_data_t      lic;
    /** Structure containing license signature data.*/
    fit_signature_data_t    *signature;
} fit_v2c_data_t;

/* Macro Functions **********************************************************/

/* Function Prototypes ******************************************************/


#endif /* __FIT_H__ */

