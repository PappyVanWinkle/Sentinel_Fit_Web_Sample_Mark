/****************************************************************************\
**
** fit_krypto.h
**
** Contains declaration for keys array used in Sentinel Fit for krypto related
** operations.
** 
** Copyright (C) 2016, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#ifndef __FIT_KRYPTO_H__
#define __FIT_KRYPTO_H__

#if !defined(FIT_CONFIG_FILE)
#include "fit_config.h"
#else
#include FIT_CONFIG_FILE
#endif

#include "fit_keys.h"
#include "fit_types.h"
#include "fit_hwdep.h"

#ifdef FIT_USE_AES_SIGNING

uint16_t aes_alg_guid = (uint16_t)FIT_KEY_SCOPE_SIGN << 12 | FIT_AES_128_OMAC_ALG_ID;
fit_algorithm_list_t aes_algorithms PROGMEM = {
    /** Number of algorithm supported crypto/signing key. */
     1,
     /** GUID having algorithm id and its scope
      * algorithm_id = 12 bits | key scope = 4 bits => algorithm_guid
      * Sentinel Fit supports upto 16 scopes and 4095 algorithms
      */
     &aes_alg_guid
};

fit_key_data_t aes_data PROGMEM = {
    /** Key data used for license verification or crypto purposes */
     (uint8_t*)aes_128_omac_sign_key,
     /** Length of above key */
     sizeof(aes_128_omac_sign_key),
     /** List of algorithm that above key will support and its scope */
     (fit_algorithm_list_t *)&aes_algorithms
};

#endif /* FIT_USE_AES_SIGNING */

#ifdef FIT_USE_RSA_SIGNING

const uint16_t rsa_256_key_len = sizeof(rsa_256_sign_pubkey)/sizeof(rsa_256_sign_pubkey[0]);

uint16_t rsa_alg_guid = (uint16_t)FIT_KEY_SCOPE_SIGN << 12 |
                                  FIT_RSA_2048_ADM_PKCS_V15_ALG_ID;

fit_algorithm_list_t rsa_algorithms PROGMEM = {
    /** Number of algorithm supported crypto/signing key. */
     1,
     /** GUID having algorithm id and its scope
      * algorithm_id = 12 bits | key scope = 4 bits => algorithm_guid
      * Sentinel Fit supports upto 16 scopes and 4095 algorithms
      */
     &rsa_alg_guid
};

fit_key_data_t rsa_data PROGMEM = {
    /** Key data used for license verification or crypto purposes */
    (uint8_t*)rsa_256_sign_pubkey,
    /** Length of above key */
    sizeof(rsa_256_sign_pubkey),
    /** List of algorithm that above key will support and its scope */
    &rsa_algorithms
};

#endif /* FIT_USE_RSA_SIGNING */

#if defined (FIT_USE_FLASH) && !defined (FIT_USE_E2)
#define FIT_READ_KEY_BYTE       FIT_READ_BYTE_FLASH
#elif defined (FIT_USE_E2) && !defined (FIT_USE_FLASH)
#define FIT_READ_KEY_BYTE       FIT_READ_BYTE_E2
#else
#define FIT_READ_KEY_BYTE       FIT_READ_BYTE_RAM
#endif // if defined (FIT_USE_FLASH) && !defined(FIT_USE_E2)

#if defined (FIT_USE_AES_SIGNING) && defined (FIT_USE_RSA_SIGNING)

fit_key_array_t fit_keys PROGMEM  = {
    /** pointer to read byte function for reading key part.*/
    (fit_read_byte_callback_t)FIT_READ_KEY_BYTE,
    /** Number of supported keys */
    2,
    /** Array of fit_key_data_t structures */
    {&aes_data,&rsa_data}
};

#elif defined (FIT_USE_AES_SIGNING) && !defined (FIT_USE_RSA_SIGNING)

fit_key_array_t fit_keys PROGMEM = {
    /** pointer to read byte function for reading key part.*/
    FIT_READ_KEY_BYTE,
    /** Number of supported keys */
    1,
    /** Array of fit_key_data_t structures */
    &aes_data
};

#elif defined (FIT_USE_RSA_SIGNING) && !defined (FIT_USE_AES_SIGNING)

fit_key_array_t fit_keys PROGMEM = {
    /** pointer to read byte function for reading key part.*/
    (fit_read_byte_callback_t)FIT_READ_KEY_BYTE,
    /** Number of supported keys */
    1,
    /** Array of fit_key_data_t structures */
    &rsa_data
};

#endif // if defined (FIT_USE_AES_SIGNING) && defined (FIT_USE_RSA_SIGNING)

#endif // ifndef __FIT_KRYPTO_H__
