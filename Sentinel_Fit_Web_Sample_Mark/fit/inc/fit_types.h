/****************************************************************************\
**
** fit_types.h
**
** Basic types used in Sentinel FIT
** 
** Copyright (C) 2016, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#ifndef __FIT_TYPES_H__
#define __FIT_TYPES_H__

/* Required Includes ********************************************************/
#ifndef _MSC_VER
#include <stdint.h>
#endif
#include "fit_status.h"

/* Constants ****************************************************************/

/* Types ********************************************************************/

/*
 * it's safe to rely on stdint types being available, since they are crucial
 * for embedded stuff; does not make any sense to introduce own types apart
 * from annoying users
 */

#ifdef _MSC_VER

typedef unsigned char           uint8_t;
typedef signed char             int8_t;
typedef unsigned short          uint16_t;
typedef signed short            int16_t;
typedef unsigned long           uint32_t;
typedef signed long             int32_t;
typedef signed long long int    int64_t;
typedef unsigned long long int  uint64_t;

#endif /* _MSC_VER */

/* Types ********************************************************************/

/** enum describing about algorithm used in Sentinel Fit project */
typedef enum fit_algorithm_id {
    /** RSA algorithm used for signing the license */
    FIT_RSA_2048_ADM_PKCS_V15_ALG_ID      = 1,
    /** AES-128 algorithm used for signing the license */
    FIT_AES_128_OMAC_ALG_ID,
    /** AES-256 algorithm used for crypto purposes in Sentinel Fit*/
    FIT_AES_256_ALG_ID,

    /** Maximum value that algorithm id can take */
    FIT_ALG_ID_MAX = 4095,
} fit_algorithm_id_t;

/** enum describing scope of algorithm id usage */
typedef enum fit_key_scope {
    /** For signing the license or sproto field (as per sproto schema) */
    FIT_KEY_SCOPE_SIGN =   1,
    /** For crypto related operations for sproto field (as per sproto schema) */
    FIT_KEY_SCOPE_CRYPT,

    /** Maximum value that key scope can take */
    FIT_KEY_SCOPE_ID_MAX = 15,

} fit_key_scope_t;

/** boolean types for Sentinel fit project */
typedef enum fit_boolean {
    /** Represent FALSE (0) value for Sentinel fit project */
    FIT_FALSE = 0,
    /** Represent TRUE (1) value for Sentinel fit project */
    FIT_TRUE,
} fit_boolean_t;

/** Structure describing list of algorithm supoorted for any crypto/signing key. */
typedef struct fit_algorithm_list {
    /** Number of algorithm supported crypto/signing key. */
    uint8_t num_of_alg;
    /** GUID having algorithm id and its scope
      * algorithm_id = 12 bits | key scope = 4 bits => algorithm_guid
      * Sentinel Fit supports upto 16 scopes and 4095 algorithms
      */
    uint16_t *algorithm_guid[];

} fit_algorithm_list_t;

/** Structure descibing key (signing/crypto) data and purpose of that key in Sentinel Fit */
typedef struct fit_key_data {
    /** Key data used for license verification or crypto purposes */
    uint8_t *key;
    /** Length of above key */
    uint16_t key_length;
    /** List of algorithm that above key will support and its scope */
    fit_algorithm_list_t *algorithms;

} fit_key_data_t;


/** Prototype of read "license/RSA public key" byte callback function.*/
typedef uint8_t (*fit_read_byte_callback_t)(const void *address);

/*
 * To access the license data and RSA public key data in differnt types of memory
 * (FLASH, E2, RAM), following structure is used.
 */
typedef struct fit_pointer
{
    /** pointer to license binary/RSA public key */
    uint8_t *data;
    /** length of license/RSA public key data.*/
    uint16_t length;
    /** pointer to read byte function for reading data part.*/
    fit_read_byte_callback_t read_byte;
}fit_pointer_t;

/** Strcuture descibing arrays of key data for Sentinel Fit and function for reading data part */
typedef struct fit_key_array {
    /** pointer to read byte function for reading key part.*/
    fit_read_byte_callback_t read_byte;
    /** Number of supported keys */
    uint8_t number_of_keys;
    /** Array of fit_key_data_t structures */
    fit_key_data_t *keys[];

} fit_key_array_t;

/** Prototype of a get_info callback function.
 *
 * @param IN  \b  tagid         \n  identifier of the value being returned in pdata
 *
 * @param IN  \b  pdata         \n  pointer to returned data
 *
 * @param IN  \b  length        \n  length of data
 *
 * @param IO  \b  stop_parse    \n  set to value FIT_TRUE to stop further calling the callback fn,
 *                                  otherwise set to value FIT_FALSE.
 *
 * @param IN  \b  context       \n  pointer to context parameter given in get info call
 */

typedef fit_status_t (*fit_get_info_callback)(uint8_t tagid,
                                              fit_pointer_t *pdata,
                                              uint16_t length,
                                              fit_boolean_t *stop_parse,
                                              void *context);

/** Prototype of a get fingerprint/deviceid data callback function.
 *
 * @param IO  \b  rawdata       \n  pointer to buffer containing the fingerprint raw data
 *
 * @param IN  \b  rawdata_size  \n  size of rawdata buffer
 *
 * @param OUT  \b  datalen      \n  pointer to integer which will length of raw data 
 *                                  returned back
 *
 */

typedef fit_status_t (*fit_fp_callback)(uint8_t *rawdata,
                                        uint8_t rawdata_size,
                                        uint16_t *datalen);

/* Macro Functions **********************************************************/

/* Extern Data **************************************************************/

/* Function Prototypes ******************************************************/

#endif /* __FIT_TYPES_H__ */

