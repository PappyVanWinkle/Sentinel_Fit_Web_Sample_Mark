/****************************************************************************\
**
** fit_omac.c
**
** Defines functionality for implementation for OMAC algorithm
** 
** Copyright (C) 2016, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#if !defined(FIT_CONFIG_FILE)
#include "fit_config.h"
#else
#include FIT_CONFIG_FILE
#endif

#ifdef FIT_USE_AES_SIGNING

#include <string.h> 
#include <stdio.h> 
#include <stddef.h>

#include "fit_omac.h"
#include "fit_debug.h"
#include "fit_internal.h"
#include "fit_parser.h"
#include "fit_mem_read.h"

void done(uint8_t *skey)
{
    (void)skey;
    return;
}

/**
 *
 * \skip fit_omac_init
 *
 * Initialize an OMAC state (One-key Message Authentication Code)
 * http://en.wikipedia.org/wiki/OMAC_%28cryptography%29
 *
 * @param IN    omac    \n The OMAC state to initialize.
 *
 * @param IN    aes     \n AES state.
 *
 * @param IN    cipher  \n The index of the desired cipher
 *
 * @param IN    key     \n Start address of the signing key in binary format.
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
static fit_status_t fit_omac_init(omac_state_t *omac,
                           fit_aes_t *aes,
                           uint16_t blocklength,
                           const fit_pointer_t *key)
{
    fit_status_t result = FIT_STATUS_UNKNOWN_ERROR;
    uint8_t x = 0, y = 0, len = 0;
    uint16_t mask = 0, msb = 0;

    if(key->read_byte == NULL || omac == NULL)
        return FIT_STATUS_INVALID_PARAM;

    /* now setup the system */
    switch (blocklength)
    {
        case 8:
            mask = 0x1B;
            len = 8;
            break;

        case 16:
            mask = 0x87;
            len = 16;
            break;

        default:
            return FIT_STATUS_INVALID_PARAM;
    }

    if((result = fit_aes_setup(aes, key, omac->key)) != FIT_STATUS_OK)
    {
        return result;
    }

    fit_memset((uint8_t *)omac->Lu[0], 0, blocklength);

    fit_aes_encrypt(aes, omac->Lu[0], omac->Lu[0], omac->key, (uint8_t*)omac->state);

    /* now do the mults, whoopy! */
    for (x = 0; x < 2; x++)
    {
        /* if msb(L * u^(x+1)) = 0 then just shift, otherwise shift and xor constant mask */
        msb = omac->Lu[x][0] >> 7;

        /* shift left */
        for (y = 0; y < (len - 1); y++)
        {
            omac->Lu[x][y] = ((omac->Lu[x][y] << 1) | (omac->Lu[x][y + 1] >> 7)) & 255;
        }
        omac->Lu[x][len - 1] = ((omac->Lu[x][len - 1] << 1) ^ (msb ? mask : 0)) & 255;

        /* copy up as require */
        if (x == 0)
        {
            fit_memcpy(omac->Lu[1], omac->Lu[0], sizeof(omac->Lu[0]));
        }
    }

    /* setup state */
    omac->buflen = 0;
    omac->blklen = len;

    fit_memset(omac->prev, 0, sizeof(omac->prev));
    fit_memset(omac->block, 0, sizeof(omac->block));

    return FIT_STATUS_OK;

} /* fit_omac_init */

/**
 *
 * \skip fit_omac_process
 *
 * Process data through OMAC.
 *
 * @param IN    omac    \n The OMAC state obtained via fit_omac_init.
 *
 * @param IN    aes     \n AES state.
 *
 * @param IN    indata  \n Start address of the input data for which OMAC to be
 *                         calculated in binary format.
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
static fit_status_t fit_omac_process(omac_state_t *omac,
                              fit_aes_t *aes,
                              const fit_pointer_t *indata)
{
    uint16_t n = 0;
    uint8_t x = 0;
    fit_pointer_t input;
    uint16_t inlen = indata->length;

    if ((omac->buflen > (uint8_t)sizeof(omac->block)) ||
        (omac->blklen > (uint8_t)sizeof(omac->block)) ||
        (omac->buflen > omac->blklen))
    {
        return FIT_STATUS_INVALID_PARAM;
    }
    fit_memset((uint8_t *)&input, 0, sizeof(fit_pointer_t));
    input.data = indata->data;
    input.length = indata->length;
    input.read_byte = indata->read_byte;

    while (inlen != 0)
    {
        /* ok if the block is full we xor in prev, encrypt and replace prev */
        if (omac->buflen == omac->blklen)
        {
            for (x = 0; x < (uint8_t)omac->blklen; x++)
            {
                omac->block[x] ^= omac->prev[x];
            }

            fit_aes_encrypt(aes, omac->block, omac->prev, omac->key,
                (uint8_t*)omac->state);
            omac->buflen = 0;
        }

        /* add bytes */

        n = fit_math_min(inlen, (uint8_t)(omac->blklen - omac->buflen));
        input.length = n;
        fitptr_memcpy(omac->block + omac->buflen, &input);

        omac->buflen  += (uint8_t)n;
        inlen -= n;
        input.data += n;
    }

    return FIT_STATUS_OK;
}

/**
 *
 * \skip fit_omac_done
 *
 * Terminate an OMAC stream.
 *
 * @param IN    omac    \n The OMAC state obtained via fit_omac_init.
 *
 * @param IN    aes     \n AES state.
 *
 * @param OUT   out     \n Contains OMAC value out of data.
 *
 * @param OUT   outlen  \n The max size and resulting size of the OMAC data.
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
static fit_status_t fit_omac_done(omac_state_t *omac,
                           fit_aes_t *aes,
                           uint8_t *out,
                           uint32_t *outlen)
        {
    uint8_t mode        = 0;
    uint8_t x           = 0;
    
    if((omac->buflen > (uint8_t)sizeof(omac->block)) ||
      (omac->blklen > (uint8_t)sizeof(omac->block)) ||
      (omac->buflen > omac->blklen))
    {
        return FIT_STATUS_INVALID_PARAM;
    }

    /* figure out mode */
    if(omac->buflen != omac->blklen)
    {
        /* add the 0x80 byte */
        omac->block[omac->buflen++] = 0x80;

        /* pad with 0x00 */
        while (omac->buflen < omac->blklen)
        {
            omac->block[omac->buflen++] = 0x00;
        }
        mode = 1;
    }
    else
    {
        mode = 0;
    }

    /* now xor prev + Lu[mode] */
    for (x = 0; x < (unsigned)omac->blklen; x++)
    {
        omac->block[x] ^= omac->prev[x] ^ omac->Lu[mode][x];
    }

    /* encrypt it */
    fit_aes_encrypt(aes, omac->block, omac->block, omac->key, (uint8_t*)omac->state);
    done((uint8_t *)&omac->key);

    /* output it */
    for (x = 0; x < (uint8_t)omac->blklen && x < *outlen; x++)
    {
        out[x] = omac->block[x];
    }
    *outlen = x;

  return FIT_STATUS_OK;

}

/**
 *
 * \skip fit_omac_memory
 *
 * Get OMAC of data passed in. OMAC will internally use AES 128 encryption.
 *
 * @param IN    blocklength    \n The index of the desired cipher.
 *
 * @param IN    key     \n Start address of the signing key in binary format,
 *                         depending on your READ_LICENSE_BYTE definition
 *
 * @param IN    indata  \n Start address of the data for which OMAC to be calculated
 *                         in binary format, depending on your READ_LICENSE_BYTE
 *                         definition
 *
 * @param OUT   out     \n Pointer to buffer that will contain OMAC value.
 *
 * @param OUT   outlen  \n The max size and resulting size of the OMAC data.
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_omac_memory(uint16_t blocklength,
                             const fit_pointer_t *key,
                             const fit_pointer_t *indata,
                             uint8_t *out, 
                             uint32_t *outlen)
{
    fit_status_t result = FIT_STATUS_UNKNOWN_ERROR;
    omac_state_t omac = {0};
    fit_aes_t aes;

    /* omac process the data */
    if ((result = fit_omac_init(&omac, &aes, blocklength, key)) != FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_ERROR, "fit_omac_init fails with error code %ld", result);
        goto bail;
    }

    if ((result = fit_omac_process(&omac, &aes, indata)) != FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_ERROR, "fit_omac_process fails with error code %ld", result);
        goto bail;
    }

    if ((result = fit_omac_done(&omac, &aes, out, outlen)) != FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_ERROR, "fit_omac_done fails with error code %ld", result);
        goto bail;
    }

    result = FIT_STATUS_OK;

bail:

    return result;
}


/**
 *
 * fit_validate_omac_signature
 *
 * This function will be used to validate omac value present in license binary
 * against calculated omac against license data. If caching is enabled then omac
 * value present in license data is compared against cached omac value.
 *
 * @param IN    license     \n Start address of the license in binary format,
 *                             depending on your READ_LICENSE_BYTE definition
 *                             e.g. in case of RAM, this can just be the memory
 *                             address of the license variable 
 *
 * @param IN    aeskey      \n Start address of the signing key in binary format,
 *                             depending on your READ_LICENSE_BYTE definition
 *
 * @return FIT_STATUS_OK on success; otherwise appropriate error code.
 *
 */
fit_status_t fit_validate_omac_signature(fit_pointer_t* license,
                                         fit_pointer_t* aeskey)
{
    fit_status_t status             = FIT_STATUS_UNKNOWN_ERROR;
    fit_context_data_t context;
    uint16_t licenselen             = 0;
    uint8_t *licaddr                = NULL;
    /** Need to optimize this as 16 bytes can be saved */
    uint8_t licenseomac[OMAC_SIZE];
    uint16_t num_fields             = 0;
    uint8_t cmacdata[OMAC_SIZE];
    uint32_t cmaclen                = OMAC_SIZE;
    fit_pointer_t licdata;

    DBG(FIT_TRACE_INFO, "[fit_validate_omac_signature]: Entry.\n");

    fit_memset((uint8_t *)&licdata, 0, sizeof(fit_pointer_t));
    fit_memset((uint8_t *)&context, 0 , sizeof(fit_context_data_t));
    fit_memset(licenseomac, 0 , sizeof(licenseomac));
    fit_memset(cmacdata, 0 , sizeof(cmacdata));
    licdata.read_byte = license->read_byte;

    // Get the OMAC of license binary and compare it with store OMAC.
    // Step 1: Get the data address in license binary where signature is stored
    // Step 2: Validate signature part if it contains omac data.
    // Step 3: Extract OMAC if omac is present.
    // Step 4. Calculate OMAC for license container data (except signature part) and compared
    //         it with stored OMAC.

    // Step 1: Get the data address in license binary where signature is stored
    context.level = FIT_STRUCT_SIGNATURE_LEVEL;
    context.index = FIT_SIGNATURE_DATA_FIELD;
    context.operation = (uint8_t)FIT_OP_GET_DATA_ADDRESS;
    // Parse license data.
    status = fit_parse_object(FIT_STRUCT_V2C_LEVEL, FIT_LICENSE_FIELD, license, &context);
    if (!(status == FIT_STATUS_OK && context.parserstatus == FIT_INFO_STOP_PARSE))
    {
        DBG(FIT_TRACE_ERROR, "Not able to get OMAC data %d\n", status);
        goto bail;
    }
    if (context.parserdata.addr == NULL)
        return FIT_STATUS_INVALID_V2C;

    licdata.data = context.parserdata.addr;
    licdata.length = OMAC_SIZE;
    // Get the passed in license data OMAC for comparison.
    fitptr_memcpy(licenseomac, &licdata);

    // Get address and length of license part in binary.
    num_fields  = read_word(license->data, license->read_byte);
    licenselen  = (uint16_t)(read_dword(license->data +
            (num_fields*FIT_PFIELD_SIZE)+FIT_PFIELD_SIZE, license->read_byte));
    licaddr     = (uint8_t *)license->data +
            ((num_fields*FIT_PFIELD_SIZE)+FIT_PFIELD_SIZE+FIT_PARRAY_SIZE);
    licdata.data = licaddr;
    licdata.length = licenselen;

    // Get OMAC of license data.
    status = fit_omac_memory(OMAC_BLOCK_LENGTH, aeskey, &licdata,
        (uint8_t *)cmacdata, &cmaclen);
    if (status != FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_CRITICAL, "OMAC algorithm fails %d\n", status);
        goto bail;
    }
    else
    {
        DBG(FIT_TRACE_INFO, "Got license OMAC value successfully \n");
    }

    // Compare license OMAC value with calculated value.
    if(fit_memcmp(licenseomac, cmacdata, OMAC_SIZE) != 0 )
    {
        DBG(FIT_TRACE_ERROR, "\nLicense OMAC does not match with calculated OMAC value.\n");
        status = FIT_STATUS_INVALID_SIGNATURE;
        goto bail;
    }
    else
    {
        DBG(FIT_TRACE_INFO, "\nLicense OMAC match with calculated OMAC value.\n");
        status = FIT_STATUS_OK;
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
    DBG(FIT_TRACE_INFO, "[fit_validate_omac_signature]: Exit.\n");

    return status;
}

#endif // ifdef FIT_USE_AES_SIGNING
