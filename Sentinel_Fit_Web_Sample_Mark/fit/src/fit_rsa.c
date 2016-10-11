/****************************************************************************\
**
** fit_rsa.c
**
** Defines functionality for rsa verification process. 
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

#ifdef FIT_USE_RSA_SIGNING

#include "fit_rsa.h"
#include "fit_debug.h"
#include "fit_internal.h"
#include "fit_mem_read.h"
#include "fit_dm_hash.h"
#include "fit_abreast_dm.h"
#include "fit_parser.h"
#include "mbedtls/pk.h"


/* Global Data  *************************************************************/

extern fit_cache_data_t fit_cache;

/* Function Definitions *****************************************************/

/**
 *
 * fit_validate_rsa_signature
 *
 * This function is to validate rsa signature and hash against rsa public key.
 * Returns FIT_STATUS_INVALID_V2C or FIT_STATUS_OK
 *
 * @param   signature   --> fit_pointer to the signature (part of license)
 * @param   hash        --> RAM pointer to hash to be verified
 * @param   key         --> fit_pointer to RSA public key
 *
 */
fit_status_t fit_validate_rsa_signature(fit_pointer_t *signature,
                                        uint8_t       *hash,
                                        fit_pointer_t *key)
{
#ifdef FIT_USE_RSA_SIGNING
    uint8_t *temp;
    int i;
    int ret = 0;
    mbedtls_pk_context pk;

    /* read pubkey into RAM */
    temp = fit_calloc(1, key->length+1);
    if (!temp) {
        return FIT_STATUS_INSUFFICIENT_MEMORY;
    }

    for (i = 0; i < key->length; i++) 
        temp[i] = key->read_byte(key->data + i);

    mbedtls_pk_init( &pk );

#ifdef FIT_USE_PEM
    ret = mbedtls_pk_parse_public_key( &pk, (const unsigned char *)temp,
                key->length + 1);
#else
    {
      unsigned char *p = temp;
      ret = mbedtls_pk_parse_subpubkey( &p, p + key->length, &pk );
    }
#endif

    fit_free(temp);
    if (ret)
    {
        DBG(FIT_TRACE_ERROR, "[fit_validate_rsa_signature] parsing public key "
            "FAILED -0x%04x\n", -ret);
        goto exit;
    }
    DBG(FIT_TRACE_INFO, "[fit_validate_rsa_signature] public key is accepted\n" );

    /* read signature from license memory */
    temp = fit_calloc(1, FIT_RSA_SIG_SIZE);
    if (!temp) {
        return FIT_STATUS_INSUFFICIENT_MEMORY;
    }
    for (i = 0; i < FIT_RSA_SIG_SIZE; i++)
        temp[i] = signature->read_byte(signature->data + i);

    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, hash, FIT_ABREAST_DM_HASH_SIZE,
                temp, FIT_RSA_SIG_SIZE);
    fit_free(temp);
    if (ret)
    {
        DBG(FIT_TRACE_ERROR, "[fit_validate_rsa_signature] verify FAILED -0x%04x\n", -ret);
        goto exit;
    }

    DBG(FIT_TRACE_INFO, "[fit_validate_rsa_signature] verify OK\n" );
    ret = 0;

 exit:
    mbedtls_pk_free( &pk );

    if (ret) return FIT_STATUS_INVALID_SIGNATURE;
#endif
    return FIT_STATUS_OK;

}

/**
 *
 * \skip fit_verify_rsa_signature
 *
 * This function is used to validate following:
 *      1. RSA signature of new license.
 *      2. New license node lock verification.
 *
 * @param IN    license     \n Pointer to fit_pointer_t structure containing license
 *                             data. To access the license data in different types of
 *                             memory (FLASH, E2, RAM), fit_pointer_t is used.
 *
 * @param IN    key     \n Pointer to fit_pointer_t structure containing rsa public key.
 *                         To access the rsa key data in different types of memory
 *                         (FLASH, E2, RAM), fit_pointer_t is used.
 *
 * @param IN    check_cache \n FIT_TRUE if RSA verification is already done; FIT_FALSE
 *                             otherwise.
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_verify_rsa_signature(fit_pointer_t *license,
                                      fit_pointer_t *key,
                                      fit_boolean_t check_cache)
{
    fit_status_t status             = FIT_STATUS_UNKNOWN_ERROR;
    uint8_t dmhash[FIT_DM_HASH_SIZE];
    fit_context_data_t context;
    fit_pointer_t fitptr;

    DBG(FIT_TRACE_INFO, "[fit_verify_rsa_signature]: license=0x%p length=%hd\n",
        license->data, license->length);
    fit_memset((uint8_t *)&context, 0 , sizeof(fit_context_data_t));
    fit_memset((uint8_t *)&fitptr, 0, sizeof(fit_pointer_t));
    fit_memset(dmhash, 0, sizeof(dmhash));

    fitptr.read_byte = license->read_byte;

    /* Check validity of license data by RSA signature check.*/
    if (fit_cache.rsa_check_done == FIT_TRUE && check_cache == FIT_TRUE)
    {
        /* Calculate Davies-Meyer-hash on the license. Write that hash into the
         * hash table.
         */
        context.level = FIT_STRUCT_V2C_LEVEL;
        context.index = FIT_LICENSE_FIELD;
        context.operation = (uint8_t)FIT_OP_PARSE_LICENSE;
        /* Get license data address in data passed in. */
        status = fit_parse_object(FIT_STRUCT_V2C_LEVEL, FIT_LICENSE_FIELD, license,
            &context);
        if (status != FIT_STATUS_OK && context.parserstatus != FIT_INFO_STOP_PARSE)
        {
            DBG(FIT_TRACE_ERROR, "Error in license parsing %d\n", status);
            goto bail;
        }

        fitptr.data = (uint8_t *) license->data;
        fitptr.length = context.length;
        /* Get the hash of data.*/
        status = fit_davies_meyer_hash(&fitptr, (uint8_t *)&dmhash);
        if (status != FIT_STATUS_OK)
        {
            DBG(FIT_TRACE_ERROR, "Error in getting Davies Meyer hash with status"
                " %d\n", status);
            goto bail;
        }
        /*
         * If calculated hash does not match with stored hash then perform license
         * validation again. 
         */
        if(fit_memcmp(fit_cache.dm_hash, dmhash, FIT_DM_HASH_SIZE) != 0 )
        {
            status = fit_lic_do_rsa_verification(license, key);
        }
    }
    else
    {
        status = fit_lic_do_rsa_verification(license, key);
    }

    /* Check the result of license validation */
    if (status != FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_CRITICAL, "fit_verify_rsa_signature failed with error "
            "code %d\n", status);
        goto bail;
    }
    else
    {
        DBG(FIT_TRACE_INFO, "fit_verify_rsa_signature successfully passed \n");
    }

    /* Validate fingerprint information present in the license */
    status = fit_validate_fp_data(license);
     if (status != FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_CRITICAL, "fit_validate_fp_data failed with error code %d\n",
            status);
        goto bail;
    }

bail:
    if (status != FIT_STATUS_OK)
    {
        fit_cache.rsa_check_done = FIT_FALSE;
        fit_memset(fit_cache.dm_hash, 0, sizeof(fit_cache.dm_hash));
    }

    return status;
}

/**
 *
 * fit_lic_do_rsa_verification
 *
 * This function will be used to validate license string. It will perform following
 * operations
 *
 * A) Check RSA signature:
 *      Calculate Hash of the license by Abreast-DM
 *      Validate RSA signature by RSA public key and license hash.
•* B) If the RSA signature has been verified, update the Hash table in RAM:
 *      Calculate Davies-Meyer-hash on the license
 *      Write that hash into the hash table.
 *
 * @param IN    license \n Pointer to fit_pointer_t structure that contains license
 *                         data that need to be validated for RSA decryption. To
 *                         access the license data in different types of memory
 *                         (FLASH, E2, RAM), fit_pointer_t is used.
 *
 * @param IN    rsakey  \n Pointer to fit_pointer_t structure that contains rsa
 *                         public key in binary format. To access the RSA public
 *                         key in different types of memory (FLASH, E2, RAM),
 *                         fit_pointer_t is used.
 *
 */
fit_status_t fit_lic_do_rsa_verification(fit_pointer_t* license,
                                         fit_pointer_t* rsakey)
{
    fit_status_t status           = FIT_STATUS_UNKNOWN_ERROR;
    fit_context_data_t context;
    fit_pointer_t licaddr;
    fit_pointer_t signature;
    uint16_t num_fields           = 0;
    uint8_t abreasthash[FIT_ABREAST_DM_HASH_SIZE];
    uint8_t dmhash[FIT_DM_HASH_SIZE];

    DBG(FIT_TRACE_INFO, "[fit_lic_do_rsa_verification]: Entry.\n");

    fit_memset((uint8_t *)&context, 0 , sizeof(fit_context_data_t));
    fit_memset((uint8_t *)&licaddr, 0, sizeof(fit_pointer_t));
    fit_memset((uint8_t *)&signature, 0, sizeof(fit_pointer_t));
    fit_memset(abreasthash, 0, sizeof(abreasthash));
    fit_memset(dmhash, 0, sizeof(dmhash));

    licaddr.read_byte = license->read_byte;
    signature.read_byte = license->read_byte;

    /*
     * Check RSA signature:
     * Step 1:   Calculate Hash of the license by Abreast-DM
     * Step 2:   Validate RSA signature by RSA public key and license hash.
     */

    /* Get RSA signature data from license string.*/
    context.level = FIT_STRUCT_SIGNATURE_LEVEL;
    context.index = FIT_SIGNATURE_DATA_FIELD;
    context.operation = (uint8_t)FIT_OP_GET_DATA_ADDRESS;
    /* Parse license data to get address where RSA signature data is stored */
    status = fit_parse_object(FIT_STRUCT_V2C_LEVEL, FIT_LICENSE_FIELD, license,
        &context);
    if (status != FIT_STATUS_OK && context.parserstatus != FIT_INFO_STOP_PARSE)
    {
        DBG(FIT_TRACE_ERROR, "Not able to get rsa data %d\n", status);
        goto bail;
    }
    if (context.parserdata.addr == NULL)
    {
        status = FIT_STATUS_INVALID_V2C;
        goto bail;
    }

    licaddr.data = context.parserdata.addr;
    signature.data = licaddr.data;
    signature.length = FIT_RSA_SIG_SIZE;

    /*
     * Step 1:  Calculate Hash of the license by Abreast-DM
     * Get address and length of license part in binary.
     */
    num_fields  = read_word(license->data, license->read_byte);
    licaddr.length  = (uint16_t)(read_dword(license->data +
        ((num_fields*FIT_PFIELD_SIZE)+FIT_PFIELD_SIZE), license->read_byte));
    licaddr.data = (uint8_t *)license->data +
        ((num_fields*FIT_PFIELD_SIZE)+FIT_PFIELD_SIZE+FIT_PARRAY_SIZE);

    /* Get Abreast DM hash of the license */
    status = fit_get_abreastdm_hash(&licaddr, abreasthash);

    if (status != FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_CRITICAL, "Error in getting AbreastDM hash, status = %d\n",
            status);
        goto bail;
    }
    else
    {
        DBG(FIT_TRACE_INFO, "Got AbreastDM hash successfully. \n");
    }

    /* Step 2: Validate RSA signature by RSA public key and license hash.*/
    status = fit_validate_rsa_signature(&signature, abreasthash, rsakey);
    if (status != FIT_STATUS_OK)
        goto bail;

    /* Calculate Davies-Meyer-hash on the license. Write that hash into the hash table.*/
    context.level = FIT_STRUCT_V2C_LEVEL;
    context.index = FIT_LICENSE_FIELD;
    context.operation = (uint8_t)FIT_OP_PARSE_LICENSE;
    /* Parse license string to get address where license data is stored */
    status = fit_parse_object(FIT_STRUCT_V2C_LEVEL, FIT_LICENSE_FIELD, license, &context);
    if (status != FIT_STATUS_OK && context.parserstatus != FIT_INFO_STOP_PARSE)
    {
        DBG(FIT_TRACE_ERROR, "Error in license parsing %d\n", status);
        goto bail;
    }

    licaddr.length = context.length;
    licaddr.data = (uint8_t *) license->data;

    /* Get the davies meyer hash of data.*/
    status = fit_davies_meyer_hash(&licaddr, (uint8_t *)&dmhash);
    if (status != FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_ERROR, "Error in getting Davies Meyer hash with status %d\n",
            status);
        goto bail;
    }
    fit_cache.rsa_check_done = FIT_TRUE;
    fit_memcpy(fit_cache.dm_hash, dmhash, FIT_DM_HASH_SIZE);

bail:
    DBG(FIT_TRACE_INFO, "[fit_lic_do_rsa_verification]: Exit.\n");

    return status;
}

#endif // #ifdef FIT_USE_RSA_SIGNING
