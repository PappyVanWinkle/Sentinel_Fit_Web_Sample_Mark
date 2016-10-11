/****************************************************************************\
**
** fit_api.h
**
** Sentinel FIT Licensing interface header file. File contains exposed interface for
** C/C++ language.
**
** Copyright (C) 2016, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#ifndef __FIT_API_H__
#define __FIT_API_H__

/* Required Includes ********************************************************/
#include "fit_types.h"

/* Constants ****************************************************************/

#ifdef __cplusplus
extern "C" {
#endif


/*
 * Define tag id for each field (as per sproto schema). So each tagid will represent
 * member/field used in sentinel fit licenses.
 */
enum fit_tag_id {
    FIT_BASE_TAG_ID_VALUE = 0,

    FIT_LICENSE_TAG_ID,
    FIT_SIGNATURE_TAG_ID,
    FIT_HEADER_TAG_ID,
    FIT_LIC_CONTAINER_TAG_ID,
    FIT_ALGORITHM_TAG_ID,
    FIT_RSA_SIG_TAG_ID,
    FIT_LICGEN_VERSION_TAG_ID,
    FIT_LM_VERSION_TAG_ID,
    FIT_UID_TAG_ID,
    FIT_FP_TAG_ID,
    FIT_ID_LC_TAG_ID,
    FIT_VENDOR_ARRAY_TAG_ID,
    FIT_VENDOR_ID_TAG_ID,
    FIT_PRODUCT_TAG_ID,
    FIT_PRODUCT_ID_TAG_ID,
    FIT_VERSION_REGEX_TAG_ID,
    FIT_PRODUCT_PART_ARRAY_TAG_ID,
    FIT_PRODUCT_PART_ID_TAG_ID,
    FIT_LIC_PROP_TAG_ID,
    FIT_FEATURE_ARRAY_TAG_ID,
    FIT_PERPETUAL_TAG_ID,
    FIT_START_DATE_TAG_ID,
    FIT_END_DATE_TAG_ID,
    FIT_COUNTER_ARRAY_TAG_ID,
    FIT_DURATION_FROM_FIRST_USE_TAG_ID,
    FIT_FEATURE_TAG_ID,
    FIT_COUNTER_TAG_ID,
    FIT_LIMIT_TAG_ID,
    FIT_SOFT_LIMIT_TAG_ID,
    FIT_IS_FIELD_TAG_ID,

    /** Please Update FIT_END_TAG_ID when adding new tag id's at bottom of list.*/
    FIT_END_TAG_ID = FIT_IS_FIELD_TAG_ID,
};

/* Forward Declarations *****************************************************/

/* Types ********************************************************************/

/* Function Prototypes ******************************************************/

/**
 *
 * \skip fit_licenf_consume_license
 *
 * This function is used to grant or deny access to different areas of functionality
 * in the software. This feature is similar to login type operation on licenses. It
 * will look for presence of feature id in the license binary.
 *
 * @param IN  \b  license       \n  Start address of the license in binary format,
 *                                  depending on your READ_LICENSE_BYTE definition
 *                                  e.g. in case of RAM, this can just be the memory
 *                                  address of the license variable 
 *
 * @param IN  \b  feature_id    \n  feature id which will be consumed/used for login
 *                                  operation.
 *
 * @param IN  \b  keys          \n  Pointer to array of key data. Also contains
 *                                  callback function to read key data in different
 *                                  types of memory(FLASH, E2, RAM).
 *
 * @return FIT_STATUS_FEATURE_EXPIRED if feature_if got expired
 * @return FIT_STATUS_INVALID_V2C if Invalid liocense binary data format.
 * @return FIT_STATUS_FEATURE_NOT_FOUND if feature id is not present in license binary.
 * @return FIT_STATUS_INVALID_LICENSE_TYPE if license type is not recognized.
 * @return FIT_STATUS_INACTIVE_LICENSE if license is not active yet.
 * @return FIT_STATUS_NO_CLOCK_SUPPORT if clock support is not present.
 * @return FIT_STATUS_INVALID_VALUE if Invalid value is found for license string passed in.
 * @return FIT_STATUS_RTC_NOT_PRESENT if real time clock is not present on hardware board
 * @return FIT_STATUS_INVALID_PARAM_1 if license string is NULL or not readable.
 * @return FIT_STATUS_INVALID_PARAM_2 if feature id is out of range.
 * @return FIT_STATUS_INVALID_PARAM_4 if rsa public key is NULL or not readable.
 *
 */
fit_status_t fit_licenf_consume_license(fit_pointer_t *license,
                                        uint32_t feature_id,
                                        fit_key_array_t *keys);

/**
 *
 * \skip fit_licenf_get_info
 *
 * This function will parse the license binary passed to it and call the user provided
 * callback function for every field data. User can take any action on receiving
 * license field data like storing values in some structure or can take some action
 * like calling consume license api with feature id etc.
 *
 * @param IN    \b  license     \n Start address of the license in binary format,
 *                                 depending on your READ_LICENSE_BYTE definition
 *                                 e.g. in case of RAM, this can just be the memory
 *                                 address of the license variable 
 *
 * @param IN    \b  callback_fn \n User provided callback function to be called by
 *                                 fit core.
 *
 * @param IO    \b  context     \n Pointer to user provided data structure.
 *
 * @return FIT_STATUS_OK on success; otherwise, returns appropriate error code.
 *
 */
fit_status_t fit_licenf_get_info(fit_pointer_t* license,
                                 fit_get_info_callback callback_fn,
                                 void *context);

/**
 *
 * \skip fit_licenf_validate_license
 *
 * This function is used to validate following:
 *      1. RSA signature of new license.
 *      2. New license node lock verification.
 *
 * @param IN    \b  license     \n Pointer to fit_pointer_t structure containing license
 *                                 data. To access the license data in different types of
 *                                 memory (FLASH, E2, RAM), fit_pointer_t is used.
 *
 * @param IN    \b  keys    \n Pointer to array of key data. Also contains callback
 *                             function to read key data in differenttypes of memory
 *                             (FLASH, E2, RAM).
 *
 * @return FIT_STATUS_OK on success; otherwise, returns appropriate error code.
 *
 */
fit_status_t fit_licenf_validate_license(fit_pointer_t *license,
                                         fit_key_array_t *keys);

/**
 *
 * \skip fit_licenf_get_version
 *
 * This function used for getting information about sentinel fit core versioning
 * information.
 *
 * @param OUT   \b  major_version   \n On return it will contain the sentinel fit
 *                                     core major version data.
 *
 * @param OUT   \b  minor_version   \n On return it will contain the sentinel fit
 *                                     core minor version data.
 *
 * @param OUT   \b  revision        \n On return it will contain the sentinel fit
 *                                     core revision data.
 *
 * @return FIT_STATUS_OK on success; otherwise, returns appropriate error code.
 *
 */
fit_status_t fit_licenf_get_version(uint8_t *major_version,
                                    uint8_t *minor_version,
                                    uint8_t *revision);

#ifdef __cplusplus
}
#endif
#endif /* __FIT_API_H__ */

