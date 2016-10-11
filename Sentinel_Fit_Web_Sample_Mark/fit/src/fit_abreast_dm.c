/****************************************************************************\
**
** fit_abreast_dm.c
**
** Defines functionality for implementation for Abreast DM hash algorithm
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

#include "fit_types.h"
#include "fit_hwdep.h"
#include "fit_aes.h"
#include "fit_abreast_dm.h"
#include "fit_internal.h"
#include "fit_dm_hash.h"
#include "fit_debug.h"

/* Constants ****************************************************************/

#define FIT_ROUNDS_256BIT_KEY_LENGTH        240

/* Global Data **************************************************************/

static uint8_t fit_aes256key[FIT_AES_256_KEY_LENGTH] = {0};

/* Functions ****************************************************************/

/**
 *
 * fit_aes256_abreastdm_init
 *
 * This function will initialize hash data to default initial value.
 *
 * @param IN    hash    \n Pointer to hash data to initialize
 *
 */
static void fit_aes256_abreastdm_init(uint8_t *hash)
{
    /* Start Hash with 0xFF */
    fit_memset(hash,0xff,32);
}

/**
 *
 * fit_aes_km_load256
 *
 * This function will update the aes key (AES algorithm) used in encryption of
 * license data.
 *
 * @param IN    key     \n Pointer to aes key data that need to be updated.
 *
 */
static void fit_aes_km_load256(uint8_t *key)
{
    fit_memcpy(fit_aes256key, key, FIT_AES_256_KEY_LENGTH);
}

/**
 *
 * fit_aes_ecb_encrypt
 *
 * This function will encrypt the data passed in based on global aes key.
 *
 * @param IN    in  \n Pointer to data that needs to be encrypted.
 *
 * @param  IN   blk_num     \n Block number in case this function is called message
 *                             greater than 16 bytes.
 *
 */
static fit_status_t fit_aes_ecb_encrypt(uint8_t *in, uint16_t blk_num)
{
    uint8_t aes_state[4][4];
    fit_status_t status = FIT_STATUS_UNKNOWN_ERROR;
    fit_aes_t aes;
    uint8_t out[FIT_AES_OUTPUT_DATA_SIZE];
    fit_pointer_t fitkey;
    uint8_t *skey = 0;

    skey = fit_calloc(1, FIT_ROUNDS_256BIT_KEY_LENGTH);
    if (NULL == skey) {
        status = FIT_STATUS_INSUFFICIENT_MEMORY;
        DBG(FIT_TRACE_ERROR, "failed to initialize memory \n");
        goto bail;
    }

    fit_memset((uint8_t *)&aes_state, 0, sizeof(aes_state));
    fit_memset(out, 0, sizeof(out));

    fit_memset((uint8_t *)&fitkey, 0, sizeof(fit_pointer_t));
    fitkey.read_byte = (fit_read_byte_callback_t) FIT_READ_BYTE_RAM;
    fitkey.data = (uint8_t *) fit_aes256key;
    fitkey.length = FIT_AES_256_KEY_LENGTH;

    /* Initialize the aes context */
    status = fit_aes_setup(&aes, &fitkey, skey);
    if (status != FIT_STATUS_OK)
    {
        DBG(FIT_TRACE_ERROR, "failed to initialize aes setup error =%d\n", status);
        goto bail;
    }

    fit_memset((uint8_t*)aes_state, 0, sizeof(aes_state));
    fit_aes_encrypt(&aes, in, out, skey, (uint8_t*)aes_state);
    fit_memcpy(in, out, 16);

bail:
    if (skey) fit_free(skey);
    return status;
}

/**
 *
 * fit_aes256_abreastdm_update
 *
 * This function will update the hash of the license data.
 *
 * @param IN    indata  \n Buffer to hold data
 *
 * @param IN    numofblks   \n Number of data block
 *
 * @param IO    Hash    \n Hash Buffer to hold thye hash value
 *
 */
void fit_aes256_abreastdm_update(uint8_t *indata, uint16_t numofblks, uint8_t *hash)
{
    uint8_t  tempbuf[FIT_AES_OUTPUT_DATA_SIZE];
    uint8_t *msg = indata;
    uint8_t *hashg = hash;
    uint8_t *hashh = hash + 16;
    uint8_t  i = 0;

    fit_memset(fit_aes256key, 0, sizeof(fit_aes256key));
    fit_memset(tempbuf, 0, sizeof(tempbuf));
    while(numofblks--)
    {
        /* Gi = Gi-1 XOR AES(Gi-1 || Hi-1Mi) */
        fit_memcpy(fit_aes256key, hashh, FIT_AES_256_KEY_LENGTH/2); 
        fit_memcpy(fit_aes256key+FIT_AES_256_KEY_LENGTH/2, msg,
            FIT_AES_256_KEY_LENGTH/2);

        fit_memcpy(tempbuf, hashg, 16);
        fit_aes_ecb_encrypt(tempbuf, 1);
        for(i=0;i<16;i++)
        {
            hashg[i] ^= tempbuf[i];
        }

        /* Hi = Hi-1 XOR AES(~ Hi-1 || Mi Gi-1) */
        fit_memcpy(fit_aes256key, msg, FIT_AES_256_KEY_LENGTH/2); 
        fit_memcpy(fit_aes256key+FIT_AES_256_KEY_LENGTH/2, hashg,
            FIT_AES_256_KEY_LENGTH/2);

        fit_memcpy(tempbuf, hashh, 16); 
        for(i=0; i<16; i++)
        {
            tempbuf[i] ^= 0xFF;
        }
        fit_aes_ecb_encrypt(tempbuf, 1);
        for(i=0;i<16;i++)
        {
            hashh[i] ^= tempbuf[i];
        }

        /* Next block */
        msg  += 16;
    }
}

/**
 *
 * fit_aes256_abreastdm_update_blk
 *
 * This function will update the hash of the license data (for one block of data)
 *
 * @param IN    indata  \n Buffer to hold data
 *
 * @param IO    hash    \n Hash Buffer to hold thye hash value
 *
 */
static void fit_aes256_abreastdm_update_blk(uint8_t *indata, uint8_t *hash)
{
    uint8_t  tempbuf[FIT_AES_OUTPUT_DATA_SIZE];
    uint8_t *msg = indata;
    uint8_t *hashg = hash;
    uint8_t *hashh = hash + 16;
    uint8_t  i = 0;

    fit_memset(tempbuf, 0, sizeof(tempbuf));
    /* Gi = Gi-1 XOR AES(Gi-1 || Hi-1Mi) */
    fit_memcpy(fit_aes256key, hashh, FIT_AES_256_KEY_LENGTH/2); 
    fit_memcpy(fit_aes256key+FIT_AES_256_KEY_LENGTH/2, msg,
        FIT_AES_256_KEY_LENGTH/2); 

    fit_memcpy(tempbuf, hashg, 16);
    fit_aes_ecb_encrypt(tempbuf, 1);
    for(i=0;i<16;i++)
    {
        hashg[i] ^= tempbuf[i];
    }

    /* Hi = Hi-1 XOR AES(~ Hi-1 || Mi Gi-1) */
    fit_memcpy(fit_aes256key, msg, FIT_AES_256_KEY_LENGTH/2); 
    fit_memcpy(fit_aes256key+FIT_AES_256_KEY_LENGTH/2, hashg,
        FIT_AES_256_KEY_LENGTH/2); 

    fit_memcpy(tempbuf, hashh, 16); 
    for(i=0; i<16; i++)
    {
        tempbuf[i] ^= 0xFF;
    }
    fit_aes_ecb_encrypt(tempbuf, 1);
    for(i=0;i<16;i++)
    {
        hashh[i] ^= tempbuf[i];
    }
}

/**
 *
 * fit_aes256_abreastdm_finalize
 *
 * This function will perform final update on hash of the license data
 *
 * @param IO    hash    \n Hash Buffer to hold the hash value
 *
 */
static void fit_aes256_abreastdm_finalize(uint8_t *hash)
{
    uint8_t i;
    uint8_t tempbuf[FIT_AES_OUTPUT_DATA_SIZE];

    fit_aes_km_load256(hash);
    /* hash[0-15] */
    fit_memcpy(tempbuf, hash, 16);
    fit_aes_ecb_encrypt(tempbuf, 1);
    for(i =0; i< 16; i++)
    {
        hash[i] ^= tempbuf[i];
    }
    /* hash[16-32] */
    fit_memcpy(tempbuf, hash+16, 16);
    fit_aes_ecb_encrypt(tempbuf, 1);
    for(i =0; i< 16; i++)
    {
        hash[i+16] ^= tempbuf[i];
    }

   return;
}

/**
 *
 * fit_get_abreastdm_hash
 *
 * This function will get the abreast dm hash of the data passed in.
 *
 * @param IN    msg     \n Pointer to data passed in for which hash needs to be
 *                         calculated.
 *
 * @param IO    hash    \n Hash Buffer to hold thye hash value
 *
 */
fit_status_t fit_get_abreastdm_hash(fit_pointer_t *msg, uint8_t *hash)
{
    uint16_t cntr           = 0;
    uint8_t tempmsg[32];
    uint16_t msglen         = 0;
    fit_pointer_t fitptr;

    fit_memset((uint8_t *)&fitptr, 0, sizeof(fit_pointer_t));
    /* Initialize the read pointer.*/
    fitptr.read_byte = msg->read_byte;

    /* Initialize hash value;*/
    fit_aes256_abreastdm_init(hash);

    fit_memset(tempmsg, 0, sizeof(tempmsg));
    /* Break data in blocks (16 bytes each) and hash the data.*/
    for (cntr = 0; cntr < msg->length; cntr+=16)
    {
        if ((cntr+16) < msg->length) 
        {
            fitptr.data = msg->data+cntr;
            fitptr.length = 16;
            fitptr_memcpy(tempmsg, &fitptr);
            fit_aes256_abreastdm_update_blk(tempmsg, hash);
        }
    }
    cntr -= 16;

    fitptr.data = msg->data+cntr;
    fitptr.length = msg->length-cntr;
    msglen = fitptr.length;
    fitptr_memcpy(tempmsg, &fitptr);

    fit_dm_hash_init(tempmsg, &msglen, msg->length);
    for (cntr = 0; cntr < msglen; cntr+=16)
    {
        fit_aes256_abreastdm_update_blk(tempmsg+cntr, hash);
    }

    fit_aes256_abreastdm_finalize(hash);

    return FIT_STATUS_OK;
}
