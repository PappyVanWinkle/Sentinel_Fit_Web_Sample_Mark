/****************************************************************************\
**
** fit_abreast_dm.h
**
** Contains declaration for strctures, enum, constants and functions used in
** abreast dm hash implementation. Abreast DM hash is performed over license data
** and internally uses AES 256 for encryption.
**
** Copyright (C) 2016, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#ifndef __FIT_ABREAST_DM_H__
#define __FIT_ABREAST_DM_H__

/* Required Includes ********************************************************/

#include "fit_alloc.h"
#include "fit_types.h"

/* Constants ****************************************************************/
 
/** Abreast DM hash output size */
#define FIT_ABREAST_DM_HASH_SIZE        0x20

/* Types ********************************************************************/

/* Function Prototypes ******************************************************/

/** This function will get the abreast dm hash of the data passed in.*/
fit_status_t fit_get_abreastdm_hash(fit_pointer_t *msg, uint8_t *hash);


#endif /* __FIT_ABREAST_DM_H__ */
