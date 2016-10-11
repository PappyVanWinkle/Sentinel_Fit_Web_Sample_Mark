/****************************************************************************\
**
** fit_parser.h
**
** Contains declaration for structures, enum, constants and functions used in
** parsing Sentinel fit based licenses.
**
** Copyright (C) 2016, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#ifndef __FIT_PARSER_H__
#define __FIT_PARSER_H__

/* Required Includes ********************************************************/
#include "fit_types.h"
#include "stddef.h"

/* Constants ****************************************************************/

/* Forward Declarations *****************************************************/
typedef unsigned char wire_type_t;

/* Types ********************************************************************/

/* Macro Functions **********************************************************/

/* Function Prototypes ******************************************************/

/** This function will parse the license data passed to it */
fit_status_t fit_parse_object(uint8_t level,
                              uint8_t index,
                              fit_pointer_t *pdata,
                              void *context);
/** Return wire type corresponding to index and level passed in.*/
wire_type_t get_field_type(uint8_t level,
                           uint8_t index);
/*
 * This function will traverse each object of an array and call appropriate
 * function to parse individual objects of an array.
 */
fit_status_t fit_parse_array(uint8_t level,
                             uint8_t index,
                             fit_pointer_t *pdata,
                             void *context);

#endif /* __FIT_PARSER_H__ */

