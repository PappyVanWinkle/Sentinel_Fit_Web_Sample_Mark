/****************************************************************************\
**
** fit_dm_hash.c
**
** Defines functionality for implementation for davies meyer hash function.
** 
** Copyright (C) 2016, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

/* Required Includes ******************************************/

#if !defined(FIT_CONFIG_FILE)
#include "fit_config.h"
#else
#include FIT_CONFIG_FILE
#endif

#ifdef FIT_USE_SYSTEM_CALLS
#include <string.h>
#endif

#include "fit_dm_hash.h"
#include "fit_aes.h"
#include "fit_internal.h"
#include "fit_debug.h"
#include "fit_hwdep.h"

/* Constants ****************************************************************/

#define FIT_DM_CIPHER_BLOCK_SIZE            0x10
#define FIT_ROUNDS_128BIT_KEY_LENGTH        0xB0
#define FIT_BITS_PER_BYTE                   8

/* Global variables *********************************************************/

/* Function Definitions *****************************************************/

/**
 *
 * \skip fit_dm_hash_init
 *
 * This function will be used to pad the data to make it’s length be an even multiple
 * of the block size and include a length encoding. This is done by padding with zeros
 * to the next size which is an odd multiple of 64 bits and then appending a 64-bit
 * big-endian encoding of the number of bits of license data length.
 *
 * @param IN    pdata   \n Pointer to data that needs to be hashed.
 *
 * @param IO    pdatalen    \n Length of last data part after data is padded and encoded.
 *
 * @param IN    msgfulllen  \n Message length for which hash needs to be calculated.
 *                             This is different than pdatalen as this function is
 *                             called for only last block of data (to avoid overuse
 *                             of stack size for long messages)
 *
 */
void fit_dm_hash_init(uint8_t *pdata, uint16_t *pdatalen, uint16_t msgfulllen)
{
    uint16_t length         = 0;
    uint16_t sizeinbits     = 0;
    uint16_t cntr           = 0;
    uint8_t zeropads        = 0;

    DBG(FIT_TRACE_INFO, "\nfit_dm_hash_init..\n");

    length = *pdatalen;
    sizeinbits= msgfulllen*FIT_BITS_PER_BYTE;
    zeropads = ((FIT_DM_CIPHER_BLOCK_SIZE/sizeof(uint16_t)) - 
        (length%(FIT_DM_CIPHER_BLOCK_SIZE/sizeof(uint16_t))));

    /* Pad with zeros to the next size which is an odd multiple of 64 bits */
    for(cntr=0; cntr < zeropads; cntr++)
    {
        pdata[length++] = 0x00;
    }
    if ((length%FIT_DM_CIPHER_BLOCK_SIZE) == 0)
    {
        for(cntr=0; cntr < FIT_DM_CIPHER_BLOCK_SIZE/sizeof(uint16_t); cntr++)
        {
            pdata[length++] = 0x00;
        }
    }

    /* Append a 64-bit big-endian encoding of the number of bits to the license data */
    pdata[length++] = 0x00;
    pdata[length++] = 0x00;
    pdata[length++] = 0x00;
    pdata[length++] = 0x00;
    pdata[length++] = 0x00;
    pdata[length++] = 0x00;
    pdata[length++] = sizeinbits >> 8;
    pdata[length++] = sizeinbits >> 0;

    *pdatalen = length;
}

/**
 *
 * \skip fit_davies_meyer_hash
 *
 * This function will be used to get the davies meyer hash of the data passed in.
 * This is performed by first splitting the data (message m) into 128 bits (m1 … mn)
 * For each of the 128 bit sub-block, calculate
 *      Hi = AES (Hi-1, mi)  XOR Hi-1
 * The final Hash is calculated as:
 *      H = AES (Hn, Hn) XOR Hn
 *
 * @param IN    pdata   \n Pointer to data for which davies meyer hash to be calculated
 *
 * @param OUT   dmhash  \n On return this will contain the davies mayer hash of data
 *                         passed in.
 *
 */
fit_status_t fit_davies_meyer_hash(fit_pointer_t *pdata, uint8_t *dmhash)
{
    fit_status_t  status            = FIT_STATUS_OK;
    uint8_t aes_state[4][4];
    uint16_t cntr                   = 0;
    uint16_t cntr2                  = 0;
    uint8_t output[FIT_AES_OUTPUT_DATA_SIZE];
    uint8_t prev_hash[FIT_DM_HASH_SIZE];
    fit_aes_t aes;
    uint8_t tempmsg[32];
    uint16_t msglen         = 0;
    fit_pointer_t fitptr;
    fit_pointer_t fitkey;
    fit_pointer_t fittempptr;
    uint8_t *skey;

    skey = fit_calloc(1, FIT_ROUNDS_128BIT_KEY_LENGTH);
    if (NULL == skey) {
        status = FIT_STATUS_INSUFFICIENT_MEMORY;
        DBG(FIT_TRACE_ERROR, "failed to initialize aes error =%d\n", status);
        goto bail;
    }

    fit_memset((uint8_t *)&fitkey, 0, sizeof(fit_pointer_t));
    fit_memset(tempmsg, 0, sizeof(tempmsg));
    fit_memset((uint8_t *)&fitptr, 0, sizeof(fit_pointer_t));
    fit_memset((uint8_t *)&fittempptr, 0, sizeof(fit_pointer_t));
    fit_memset(prev_hash, 0xFF, FIT_DM_HASH_SIZE);
    /* Initialize the read pointer.*/
    fitptr.read_byte = pdata->read_byte;
    fitkey.read_byte = (fit_read_byte_callback_t) FIT_READ_BYTE_RAM;

    /*
     * For each of the 128 bit sub-block, calculate
     *      Hi = AES (Hi-1, mi)  XOR Hi-1
     */
    for (cntr = 0; cntr < pdata->length; cntr+=16)
    {
        if ((cntr+16) < pdata->length)
        {
            /* Initialize the aes context */
            fittempptr.data = (pdata->data)+cntr;
            fittempptr.length = FIT_AES_128_KEY_LENGTH;
            fittempptr.read_byte = pdata->read_byte;

            fitptr_memcpy(tempmsg, &fittempptr);
            fitkey.data = (uint8_t *)tempmsg;
            fitkey.length = FIT_AES_128_KEY_LENGTH;
            status = fit_aes_setup(&aes, &fitkey, skey);
            if (status != FIT_STATUS_OK)
            {
                DBG(FIT_TRACE_ERROR, "failed to initialize aes setup error =%d\n",
                    status);
                goto bail;
            }

            fit_memset((uint8_t*)aes_state, 0, sizeof(aes_state));
            fit_memset((uint8_t*)output, 0, sizeof(output));
            /* Encrypt data (AES 128) */
            fit_aes_encrypt(&aes, prev_hash, output, skey, (uint8_t*)aes_state);
            for (cntr2 = 0; cntr2 < 16; cntr2++)
            {
                dmhash[cntr2] = output[cntr2] ^ prev_hash[cntr2];
            }
            fit_memcpy(prev_hash, dmhash, 16);
        }
    }
    cntr -= 16;

    fit_memset(tempmsg, 0, sizeof(tempmsg));
    /*
     * Pad the last block of data (last block will always be less than 16 bytes)
     * and calculate Hi = AES (Hi-1, mi)  XOR Hi-1 
     */
    fitptr.data = pdata->data+cntr;
    fitptr.length = pdata->length-cntr;
    msglen = fitptr.length;
    fitptr_memcpy(tempmsg, &fitptr);

    /* Do padding for the last block of data.*/
    fit_dm_hash_init(tempmsg, &msglen, pdata->length);
    /*
     * For each of the 128 bit sub-block, calculate
     *      Hi = AES (Hi-1, mi)  XOR Hi-1
     */
    for (cntr = 0; cntr < msglen; cntr+=16)
    {
        /* Initialize the aes context */
        fitkey.data = tempmsg+cntr;
        fitkey.length = FIT_AES_128_KEY_LENGTH;
        status = fit_aes_setup(&aes, &fitkey, skey);
        if (status != FIT_STATUS_OK)
        {
            DBG(FIT_TRACE_ERROR, "failed to initialize aes setup error =%d\n",
                status);
            goto bail;
        }

        fit_memset((uint8_t*)aes_state, 0, sizeof(aes_state));
        fit_memset((uint8_t*)output, 0, sizeof(output));
        /* Encrypt data (AES 128) */
        fit_aes_encrypt(&aes, prev_hash, output, skey, (uint8_t*)aes_state);
        for (cntr2 = 0; cntr2 < 16; cntr2++)
        {
            dmhash[cntr2] = output[cntr2] ^ prev_hash[cntr2];
        }
        fit_memcpy(prev_hash, dmhash, 16);
    }

    /*
     * The final Hash is calculated as:
     *      H = AES (Hn, Hn) XOR Hn
     * Initialize the aes context
     */
    fitkey.data = prev_hash;
    fitkey.length = FIT_AES_128_KEY_LENGTH;
    status = fit_aes_setup(&aes, &fitkey, skey);
    if (status != FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_ERROR, "failed to initialize aes setup error =%d\n", status);
        goto bail;
    }

    fit_memset((uint8_t*)aes_state, 0, sizeof(aes_state));
    fit_memset((uint8_t*)output, 0, sizeof(output));
    /* Encrypt data (AES 128) */
    fit_aes_encrypt(&aes, prev_hash, output, skey, (uint8_t*)aes_state);
    for (cntr2 = 0; cntr2 < 16; cntr2++)
    {
        dmhash[cntr2] = output[cntr2] ^ prev_hash[cntr2];
    }

bail:
    if (skey) fit_free(skey);
    return status;
}

