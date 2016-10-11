/****************************************************************************\
**
** fit_debug.c
**
** Defines functionality for printing debug messages or fit core logging.
** 
** Copyright (C) 2016, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#if !defined(FIT_CONFIG_FILE)
#include "fit_config.h"
#else
#include FIT_CONFIG_FILE
#endif

#include <stdlib.h>
#include <stdio.h>

#include "fit_debug.h"
#include "fit_hwdep.h"
#include "fit_internal.h"

/* Global Data **************************************************************/

uint16_t fit_trace_flags = FIT_TRACE_ALL;

/**
 *
 * \skip fit_putc
 *
 * This function will send/print the character to output screen
 *
 * @param IN    \b  c \n character to be send/print to output screen.
 *
 */
void fit_putc(char c)
{
    if (c == '\n') 
        FIT_UART_WRITECHAR('\r');
        
    FIT_UART_WRITECHAR(c);
}

/**
 *
 * \skip fit_printf
 *
 * This function will print the data to output screen
 *
 * @param IN    \b  trace_flags \n Logging type (Info, error, critical etc)
 *
 * @param IN    \b  format \n Data to be send/print to output screen.
 *
 */

static char write_buffer[256];

EXTERNC void fit_printf(uint16_t trace_flags, const char *format, ...)
{
    char *s;
    uint16_t len = 0;
    va_list arg;
    
    if ( (fit_trace_flags & trace_flags) || (trace_flags == 0) )
    {
        s = write_buffer;
        va_start (arg, format);
#ifdef USE_VSPRINTF_P
        len = vsnprintf_P (write_buffer, sizeof(write_buffer), format, arg);
#else
        len = vsnprintf(write_buffer, sizeof(write_buffer), format, arg);
#endif
        va_end (arg);

        if (len > sizeof(write_buffer)) {
            len = sizeof(write_buffer);
        }

        if(len)
        {
#ifdef FIT_USE_COMX
            comx_packet_transaction(LOGGER, 0, (uint8_t *) write_buffer, len, NULL);
#else
            while (*s)
                fit_putc(*s++);
#endif // FIT_USE_COMX
        }
    }
}

/**
 *
 * \skip fit_get_error_str
 *
 * This function gets descriptive string for a fit status code
 *
 * @param IN    \b  st \n Sentinel Fit status code.
 *
 */
const char *fit_get_error_str (fit_status_t st)
{
    switch (st)
    {
        case FIT_STATUS_OK:                            return "FIT_STATUS_OK";
        case FIT_STATUS_INSUFFICIENT_MEMORY:           return "FIT_STATUS_INSUFFICIENT_MEMORY";
        case FIT_STATUS_INVALID_FEATURE_ID:            return "FIT_STATUS_INVALID_FEATURE_ID";
        case FIT_STATUS_INVALID_V2C:                   return "FIT_STATUS_INVALID_V2C";
        case FIT_STATUS_ACCESS_DENIED:                 return "FIT_STATUS_ACCESS_DENIED";
        case FIT_STATUS_INVALID_VALUE:                 return "FIT_STATUS_INVALID_VALUE";
        case FIT_STATUS_REQ_NOT_SUPPORTED:             return "FIT_STATUS_REQ_NOT_SUPPORTED";
        case FIT_STATUS_UNKNOWN_ALGORITHM:             return "FIT_STATUS_UNKNOWN_ALGORITHM";
        case FIT_STATUS_FEATURE_NOT_FOUND:             return "FIT_STATUS_FEATURE_NOT_FOUND";
        case FIT_STATUS_INVALID_LICGEN_VER:            return "FIT_STATUS_INVALID_LICGEN_VER";
        case FIT_STATUS_INVALID_SIG_ID:                return "FIT_STATUS_INVALID_SIG_ID";
        case FIT_STATUS_FEATURE_EXPIRED:               return "FIT_STATUS_FEATURE_EXPIRED";
        case FIT_STATUS_LIC_CACHING_ERROR:             return "FIT_STATUS_LIC_CACHING_ERROR";
        case FIT_STATUS_INVALID_PRODUCT:               return "FIT_STATUS_INVALID_PRODUCT";
        case FIT_STATUS_INVALID_PARAM:                 return "FIT_STATUS_INVALID_PARAM";
        case FIT_STATUS_INVALID_PARAM_1:               return "FIT_STATUS_INVALID_PARAM_1";
        case FIT_STATUS_INVALID_PARAM_2:               return "FIT_STATUS_INVALID_PARAM_2";
        case FIT_STATUS_INVALID_PARAM_3:               return "FIT_STATUS_INVALID_PARAM_3";
        case FIT_STATUS_INVALID_PARAM_4:               return "FIT_STATUS_INVALID_PARAM_4";
        case FIT_STATUS_INVALID_PARAM_5:               return "FIT_STATUS_INVALID_PARAM_5";
        case FIT_STATUS_INVALID_WIRE_TYPE:             return "FIT_STATUS_INVALID_WIRE_TYPE";
        case FIT_STATUS_INTERNAL_ERROR:                return "FIT_STATUS_INTERNAL_ERROR";
        case FIT_STATUS_INVALID_KEYSIZE:               return "FIT_STATUS_INVALID_KEYSIZE";
        case FIT_STATUS_INVALID_VENDOR_ID:             return "FIT_STATUS_INVALID_VENDOR_ID";
        case FIT_STATUS_INVALID_PRODUCT_ID:            return "FIT_STATUS_INVALID_PRODUCT_ID";
        case FIT_STATUS_INVALID_CONTAINER_ID:          return "FIT_STATUS_INVALID_CONTAINER_ID";
        case FIT_STATUS_LIC_FIELD_PRESENT:             return "FIT_STATUS_LIC_FIELD_PRESENT";
        case FIT_STATUS_INVALID_LICENSE_TYPE:          return "FIT_STATUS_INVALID_LICENSE_TYPE";
        case FIT_STATUS_LIC_EXP_NOT_SUPP:              return "FIT_STATUS_LIC_EXP_NOT_SUPP";
        case FIT_STATUS_INVALID_START_DATE:            return "FIT_STATUS_INVALID_START_DATE";
        case FIT_STATUS_INVALID_END_DATE:              return "FIT_STATUS_INVALID_END_DATE";
        case FIT_STATUS_INACTIVE_LICENSE:              return "FIT_STATUS_INACTIVE_LICENSE";
        case FIT_STATUS_RTC_NOT_PRESENT:               return "FIT_STATUS_RTC_NOT_PRESENT";
        case FIT_STATUS_NO_CLOCK_SUPPORT:              return "FIT_STATUS_NO_CLOCK_SUPPORT";
        case FIT_STATUS_INVALID_FIELD_LEN:             return "FIT_STATUS_INVALID_FIELD_LEN";
        case FIT_STATUS_DATA_MISMATCH_ERROR:           return "FIT_STATUS_DATA_MISMATCH_ERROR";
        case FIT_STATUS_NODE_LOCKING_NOT_SUPP:         return "FIT_STATUS_NODE_LOCKING_NOT_SUPP";
        case FIT_STATUS_FP_MAGIC_NOT_VALID:            return "FIT_STATUS_FP_MAGIC_NOT_VALID";
        case FIT_STATUS_UNKNOWN_FP_ALGORITHM:          return "FIT_STATUS_UNKNOWN_FP_ALGORITHM";
        case FIT_STATUS_FP_MISMATCH_ERROR:             return "FIT_STATUS_FP_MISMATCH_ERROR";
        case FIT_STATUS_INVALID_DEVICE_ID_LEN:         return "FIT_STATUS_INVALID_DEVICE_ID_LEN";
        case FIT_STATUS_INVALID_SIGNATURE:             return "FIT_STATUS_INVALID_SIGNATURE";
        case FIT_STATUS_UNKNOWN_ERROR:                 return "FIT_STATUS_UNKNOWN_ERROR";        
        case FIT_STATUS_NO_RSA_SUPPORT:                return "FIT_STATUS_NO_RSA_SUPPORT";
        case FIT_STATUS_NO_AES_SUPPORT:                return "FIT_STATUS_NO_AES_SUPPORT";
        case FIT_STATUS_INVALID_KEY_SCOPE:             return "FIT_STATUS_INVALID_KEY_SCOPE";
        case FIT_STATUS_KEY_NOT_PRESENT:               return "FIT_STATUS_KEY_NOT_PRESENT";
        case FIT_STATUS_INVALID_RSA_PUBKEY:            return "FIT_STATUS_INVALID_RSA_PUBKEY";
        default:;
    }
    return "UNKNOWN ERROR";
}

