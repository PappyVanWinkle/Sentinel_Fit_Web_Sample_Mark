/****************************************************************************\
**
** fit_demo_getinfo.c
**
** Defines functionality for get info API on sentinel fit based licenses for 
** embedded devices.
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
#include <stdio.h>
#endif

#include "fit_alloc.h"
#include "fit_parser.h"
#include "fit_internal.h"
#include "fit_debug.h"
#include "fit_mem_read.h"

/* Constants ****************************************************************/

#define TEMP_BUF_LEN 41

/* Global Data **************************************************************/

/* Function Prototypes ******************************************************/

/*
 * free memory allocated while traversing license data
 */
static void freelicensedata (void *context);
/*
 * print human readable summary of license data
 */
static void printlicensedata (void *context);

/* Functions ****************************************************************/

/**
 *
 * packet_malloc
 *
 * This function returns a pointer to a chunk of memory of size length
 */

static uint8_t *packet_malloc(uint16_t length)
{
    return fit_calloc(1, length);
}


/**
 *
 * fit_getlicensedata_cb
 *
 * This function will get complete license information for embedded devices like
 * license header information, license signature data, vendor information, and like
 * license property information i.e. license is perpetual or not, start date, end date,
 * counter information etc.
 *
 * @param IN    tagid   \n define unique field in sentinel fit license.
 *
 * @param IN    pdata   \n Pointer to data that contains information related to tagid.
 *
 * @param IN    length  \n Length of the data requested in bytes.
 *
 * @param IO    stop_parse  \n set to value FIT_TRUE to stop further calling the callback fn,
 *                             otherwise set to value FIT_FALSE.
 *
 * @param IO    context \n Pointer to structure that will contain requested information.
 *
 */
fit_status_t fit_getlicensedata_cb (uint8_t tagid,
                                    fit_pointer_t *pdata,
                                    uint16_t length,
                                    fit_boolean_t *stop_parse,
                                    void *context)
{
    fit_status_t status     = FIT_STATUS_OK;
    fit_v2c_data_t *v2c     = (fit_v2c_data_t *)context;
    /* cur_prod will be pointer to current product ID.*/
    static fit_product_data_t *cur_prod = NULL;
    /*
     * There can be multiple features per product in V2C. cur_feat will be pointer to
     * current feature ID.
     */
    static fit_feature_data_t *cur_feat = NULL;
    /*
     * There can be multiple license model define in V2C. cur_prod_part will be pointer to
     * current license model
     */
    static fit_prodpart_data_t *cur_prod_part = NULL;
    fit_pointer_t fitptr;


    DBG(FIT_TRACE_INFO, "User provided callback function\n");
    /* Validate parameters.*/
    if (pdata == NULL)
        return FIT_STATUS_INVALID_PARAM_2;
    if (v2c == NULL)
        return FIT_STATUS_INVALID_PARAM_4;

    fit_memset((uint8_t *)&fitptr, 0, sizeof(fit_pointer_t));
    fitptr.read_byte = pdata->read_byte;
    /* Get the information based on tag id.*/
    switch(tagid) {

    /* Start of license data. Here we can re-initialized static variables.*/
    case FIT_LICENSE_TAG_ID:
        DBG(FIT_TRACE_INFO, "FIT_LICENSE_TAG_ID\n");
        cur_prod = NULL;
        cur_feat = NULL;
        cur_prod_part = NULL;
        break;

    /* tag for signature data.*/
    case FIT_SIGNATURE_TAG_ID:
        DBG(FIT_TRACE_INFO, "FIT_SIGNATURE_TAG_ID\n");
        /* Allocate memory for license signature information.*/
        v2c->signature = (fit_signature_data_t *)packet_malloc(sizeof(fit_signature_data_t));
        if (v2c->signature == NULL)
            /* Return FIT_STATUS_INSUFFICIENT_MEMORY if memory was not sufficient */
            status = FIT_STATUS_INSUFFICIENT_MEMORY;
        else
            *stop_parse = FIT_FALSE;
        break;

    /* tag for header data.*/
    case FIT_HEADER_TAG_ID:
        break;

    /* tag for license container data.*/
    case FIT_LIC_CONTAINER_TAG_ID:
        DBG(FIT_TRACE_INFO, "FIT_LIC_CONTAINER_TAG_ID\n");
        /* Allocate memory for license container information.*/
        v2c->lic.cont = (fit_container_data_t *)packet_malloc(sizeof(fit_container_data_t));
        if (v2c->lic.cont == NULL)
            /* Return FIT_STATUS_INSUFFICIENT_MEMORY if memory was not sufficient */
            status = FIT_STATUS_INSUFFICIENT_MEMORY;
        else
        {
            v2c->lic.cont->id = 0;
            v2c->lic.cont->vendor = NULL;
            *stop_parse = FIT_FALSE;
        }

        break;

    /* tag for algorithm used.*/
    case FIT_ALGORITHM_TAG_ID:
        DBG(FIT_TRACE_INFO, "FIT_ALGORITHM_TAG_ID\n");
        if (v2c->signature != NULL)
        {
            /* Get the algorithm used for signing sentinel fit based licenses.*/
            v2c->signature->algid = read_word(pdata->data, pdata->read_byte)/2 - 1;
            *stop_parse = FIT_FALSE;
        }
        else
            status = FIT_STATUS_INVALID_VALUE;

        break;

    /* tag for licgen version.*/
    case FIT_LICGEN_VERSION_TAG_ID:
        DBG(FIT_TRACE_INFO, "FIT_LICGEN_VERSION_TAG_ID\n");
        /* Get the licgen version used for creating licenses.*/
        v2c->lic.header.licgen_version = read_word(pdata->data, pdata->read_byte)/2 - 1;
        DBG(FIT_TRACE_INFO, "v2c->lic.header.licgen_version=%d\n", v2c->lic.header.licgen_version);
        *stop_parse = FIT_FALSE;
        break;

    /* tag for LM version.*/
    case FIT_LM_VERSION_TAG_ID:
        DBG(FIT_TRACE_INFO, "FIT_LM_VERSION_TAG_ID\n");
        /* Get the LM version value.*/
        v2c->lic.header.lm_version = read_word(pdata->data, pdata->read_byte)/2 - 1;
        DBG(FIT_TRACE_INFO, "v2c->lic.header.lm_version=%d\n", v2c->lic.header.lm_version);
        *stop_parse = FIT_FALSE;
        break;

    /* tag for license unique UID value.*/
    case FIT_UID_TAG_ID:
        DBG(FIT_TRACE_INFO, "FIT_UID_TAG_ID\n");
        /* Get the license unique UID value.*/
        fitptr.data = pdata->data;
        fitptr.length = FIT_UID_LEN;
        
        fitptr_memcpy(v2c->lic.header.uid, &fitptr);
        *stop_parse = FIT_FALSE;
        break;

#ifdef FIT_USE_NODE_LOCKING
    /* tag for fingerprint data.*/
    case FIT_FP_TAG_ID:
        DBG(FIT_TRACE_INFO, "FIT_FINGERPRINT_FIELD\n");
        /* Get the fingerprint information.*/
        fit_get_fingerprint(pdata, &(v2c->lic.header.licensefp));
        *stop_parse = FIT_FALSE;
        break;
#endif /* ifdef FIT_USE_NODE_LOCKING */

    /* tag for license container ID. */
    case FIT_ID_LC_TAG_ID:
        DBG(FIT_TRACE_INFO, "FIT_ID_LC_TAG_ID\n");
        if (v2c->lic.cont == NULL)
            status = FIT_STATUS_INVALID_VALUE;
        else
        {
            /* Get the license container ID value.*/
            v2c->lic.cont->id = read_dword(pdata->data, pdata->read_byte)/2 - 1;
            *stop_parse = FIT_FALSE;
        }
        break;

    /* Tag for vendor information.*/
    case FIT_VENDOR_ARRAY_TAG_ID:
        DBG(FIT_TRACE_INFO, "FIT_VENDOR_ARRAY_TAG_ID\n");
        if (v2c->lic.cont == NULL)
            status = FIT_STATUS_INVALID_VALUE;
        else
        {
            v2c->lic.cont->vendor = (fit_vendor_data_t *)packet_malloc(sizeof(fit_vendor_data_t));
            if (v2c->lic.cont->vendor == NULL)
                /* Return FIT_STATUS_INSUFFICIENT_MEMORY if memory was not sufficient */
                status = FIT_STATUS_INSUFFICIENT_MEMORY;
            else
                *stop_parse = FIT_FALSE;
        }
        break;

    /* Tag for vendor ID.*/
    case FIT_VENDOR_ID_TAG_ID:
        DBG(FIT_TRACE_INFO, "FIT_VENDOR_ID_TAG_ID\n");
        if (v2c->lic.cont == NULL || v2c->lic.cont->vendor == NULL)
            status = FIT_STATUS_INVALID_VALUE;
        else
        {
            /* Get the vendor ID value.*/
            if (length == FIT_PFIELD_SIZE)
                v2c->lic.cont->vendor->vendorid = (uint16_t)read_word(pdata->data, pdata->read_byte)/2 -1;
            else if (length == FIT_PARRAY_SIZE)
                v2c->lic.cont->vendor->vendorid = read_dword(pdata->data, pdata->read_byte);
            *stop_parse = FIT_FALSE;
        }
        break;

    case FIT_PRODUCT_TAG_ID:
        break;

    /* Tag for product id.*/
    case FIT_PRODUCT_ID_TAG_ID:
        DBG(FIT_TRACE_INFO, "FIT_PRODUCT_TAG_ID\n");
        if (v2c->lic.cont == NULL || v2c->lic.cont->vendor == NULL)
            status = FIT_STATUS_INVALID_VALUE;
        else
        {
            cur_prod = (fit_product_data_t *)&(v2c->lic.cont->vendor->prod);
            /* get the product id.*/
            if (length == FIT_PFIELD_SIZE)
                cur_prod->prodid = read_word(pdata->data, pdata->read_byte)/2 -1;
            else if (length == FIT_PARRAY_SIZE)
                cur_prod->prodid = read_dword(pdata->data, pdata->read_byte);
            *stop_parse = FIT_FALSE;
        }
        break;

    /* tag for version regex.*/
    case FIT_VERSION_REGEX_TAG_ID:
        DBG(FIT_TRACE_INFO, "FIT_VERSION_REGEX_TAG_ID\n");
        if (v2c->lic.cont == NULL || v2c->lic.cont->vendor == NULL || cur_prod == NULL)
            status = FIT_STATUS_INVALID_VALUE;
        else
        {
            fitptr.data = pdata->data;
            fitptr.length = FIT_UID_LEN;	
            /* to change FIT_UID_LEN */
            fitptr_memcpy((uint8_t *)cur_prod->verregex, &fitptr);
            *stop_parse = FIT_FALSE;
        }
        break;

    /* Tag for product part information.*/
    case FIT_PRODUCT_PART_ARRAY_TAG_ID:
        DBG(FIT_TRACE_INFO, "FIT_PRODUCT_PART_ARRAY_TAG_ID\n");
        break;

    case FIT_PRODUCT_PART_ID_TAG_ID:
        DBG(FIT_TRACE_INFO, "FIT_PRODUCT_PART_ID_TAG_ID\n");
        if (cur_prod == NULL)
            status = FIT_STATUS_INVALID_VALUE;
        else
        {
            /*
             * Get pointer to first product part id. If NULL, means this is first
             * product part in the license.
             * If not NULL, create a linked list of product part id's (first product 
             * part at head of linked list)
             */
            fit_prodpart_data_t *prodpart = cur_prod->prodpart;
            fit_prodpart_data_t *lastprodpart = NULL;
            if (prodpart == NULL)
            {
                prodpart = (fit_prodpart_data_t *)packet_malloc(sizeof(fit_prodpart_data_t));
                if (prodpart == NULL)
                    /* Return FIT_STATUS_INSUFFICIENT_MEMORY if memory was not sufficient */
                    return FIT_STATUS_INSUFFICIENT_MEMORY;
                else
                    cur_prod->prodpart = prodpart;
            }
            else
            {
                /* Create a linked list of product id's. */
                while(prodpart != NULL)
                {
                    lastprodpart = prodpart;
                    prodpart = prodpart->next;
                }

                prodpart = (fit_prodpart_data_t *)packet_malloc(sizeof(fit_prodpart_data_t));
                if (prodpart == NULL)
                    /* Return FIT_STATUS_INSUFFICIENT_MEMORY if memory was not sufficient */
                    return FIT_STATUS_INSUFFICIENT_MEMORY;
                else
                    lastprodpart->next = prodpart;
            }

            if (status == FIT_STATUS_OK)
            {
                prodpart->next = NULL;
                /* cur_prod will contain pointer to current product id in license data. */
                cur_prod_part = prodpart;

                /* get the product id.*/
                if (length == FIT_PFIELD_SIZE)
                    cur_prod_part->partid = read_word(pdata->data, pdata->read_byte)/2 -1;
                else if (length == FIT_PARRAY_SIZE)
                    cur_prod_part->partid = read_dword(pdata->data, pdata->read_byte);

                *stop_parse = FIT_FALSE;
            }

        }
        break;

    /* tag for license properties */
    case FIT_LIC_PROP_TAG_ID:
        DBG(FIT_TRACE_INFO, "FIT_LIC_PROP_TAG_ID\n");
        if (cur_prod_part == NULL)
            status = FIT_STATUS_INVALID_VALUE;
        else
        {
            /* Initialize the license properties members (to avoid garbage values) */
            cur_prod_part->properties.feat = NULL;
            cur_prod_part->properties.enddate = 0;
            cur_prod_part->properties.startdate = 0;
            cur_prod_part->properties.perpetual = 0;

            *stop_parse = FIT_FALSE;
        }
        break;

    /* tag for feature array */
    case FIT_FEATURE_ARRAY_TAG_ID:
        break;

    /* tag for feature id.*/
    case FIT_FEATURE_TAG_ID:
    {
        if (cur_prod_part == NULL)
            status = FIT_STATUS_INVALID_VALUE;
        else
        {
            /*
             * Get pointer to first feature id in product. If NULL, means this is
             * first feature in the product.
             * If not NULL, create a linked list of features id's (first feature at
             * head of linked list)
             */
            fit_feature_data_t *features = cur_prod_part->properties.feat;
            fit_feature_data_t *lastfeat = NULL;
            if (features == NULL)
            {
                features = (fit_feature_data_t *)packet_malloc(sizeof(fit_feature_data_t));
                if (features == NULL)
                    /* Return FIT_STATUS_INSUFFICIENT_MEMORY if memory was not sufficient */
                    return FIT_STATUS_INSUFFICIENT_MEMORY;
                else
                    cur_prod_part->properties.feat = features;
            }
            else
            {
                /* create a linked list of feature's ID. */
                while(features != NULL)
                {
                    lastfeat = features;
                    features = features->next;
                }

                features = (fit_feature_data_t *)packet_malloc(sizeof(fit_feature_data_t));
                if (features == NULL)
                    /* Return FIT_STATUS_INSUFFICIENT_MEMORY if memory was not sufficient */
                    return FIT_STATUS_INSUFFICIENT_MEMORY;
                else
                    lastfeat->next = features;
            }

            /* cur_feat will contain pointer to current feature id in license data.*/
            if (status == FIT_STATUS_OK)
            {
                features->next = NULL;
                cur_feat = features;
                /* get the feature id.*/
                if (length == FIT_PFIELD_SIZE)
                    cur_feat->featid = read_word(pdata->data, pdata->read_byte)/2 - 1;
                else if (length == FIT_PARRAY_SIZE)
                    cur_feat->featid = read_dword(pdata->data, pdata->read_byte);
                *stop_parse = FIT_FALSE;
            }
        }
    }
        break;

    /* tag for perpatual license */
    case FIT_PERPETUAL_TAG_ID:
        if (cur_prod_part == NULL)
            status = FIT_STATUS_INVALID_VALUE;
        else
        {
            /* check whether license is perpetual or not.*/
            cur_prod_part->properties.perpetual = pdata->read_byte(pdata->data)/2 - 1;
            cur_prod_part->lictype = FIT_LIC_PERPETUAL;
            *stop_parse = FIT_FALSE;
        }
        break;

    /* tag for start date.*/
    case FIT_START_DATE_TAG_ID:
        if (cur_prod_part == NULL)
            status = FIT_STATUS_INVALID_VALUE;
        else
        {
            /* Get the start date value.*/
            cur_prod_part->properties.startdate = read_dword(pdata->data, pdata->read_byte);
            *stop_parse = FIT_FALSE;
        }
        break;

    /* tag for end date.*/
    case FIT_END_DATE_TAG_ID:
        if (cur_prod_part == NULL)
            status = FIT_STATUS_INVALID_VALUE;
        else
        {
            /* Get the end date value.*/
            cur_prod_part->properties.enddate = read_dword(pdata->data, pdata->read_byte);
            cur_prod_part->lictype = FIT_LIC_EXPIRATION_BASED;
            *stop_parse = FIT_FALSE;
        }
        break;

    case FIT_DURATION_FROM_FIRST_USE_TAG_ID:
        if (cur_prod_part == NULL)
            status = FIT_STATUS_INVALID_VALUE;
        else
        {
            /* Get the end date value.*/
            cur_prod_part->lictype = FIT_LIC_TIME_BASED;
            *stop_parse = FIT_FALSE;
        }
        break;

    default:
        break;

    }

    return status;
}

/**
 *
 * freelicensedata
 *
 * This function will free dynamic memory allocated in get info callback function.
 *
 * @param IO    context \n Pointer to structure that contains license data.
 *
 */
void freelicensedata (void *context)
{
    fit_v2c_data_t *v2c           = (fit_v2c_data_t *)context;

    DBG(FIT_TRACE_INFO, "*** Free License Data ******************************************\n");
    if (v2c != NULL)
    {
        if (v2c->signature != NULL)
        {
            /* free memory associated with signature data */
            fit_free((uint8_t *)v2c->signature);
            v2c->signature = NULL;
        }
        if (v2c->lic.cont != NULL)
        {
            if (v2c->lic.cont->vendor != NULL)
            {
                if (v2c->lic.cont->vendor->prod.prodpart != NULL)
                {
                    /* Get pointer to first product in the license */
                    fit_prodpart_data_t *prodpart = v2c->lic.cont->vendor->prod.prodpart;

                    while(prodpart != NULL)
                    {
                        fit_prodpart_data_t *delprod = prodpart;
                        /* Get pointer to first feature in the product */
                        fit_feature_data_t *featarray = prodpart->properties.feat;
                        while(featarray != NULL)
                        {
                            fit_feature_data_t *delfeat = featarray;

                            featarray = featarray->next;
                            /* Free feature information for one product ID. */
                            fit_free((uint8_t *)delfeat);
                        }
                        prodpart = prodpart->next;
                        /* Free memory associated with product data. */
                        fit_free((uint8_t *)delprod);
                    }
                }
                /* Free memory associated with vendor data.*/
                fit_free((uint8_t *)(v2c->lic.cont->vendor));
            }
            /* Free memory associated with license container data.*/
            fit_free((uint8_t *)(v2c->lic.cont));
        }
    }
}

/**
 *
 * printlicensedata
 *
 * This function will print license information.
 *
 * @param IO    context \n Pointer to structure that contains license data.
 *
 */
void printlicensedata (void *context)
{
    fit_v2c_data_t *v2c       = (fit_v2c_data_t *)context;
    uint8_t cntr            = 0;

    DBG(FIT_TRACE_INFO, "*** License Data ***********************************************\n");
    if (v2c != NULL)
    {
        if (v2c->signature != NULL)
        {
            DBG(FIT_TRACE_INFO, "Algorithm used for signing license data = %d\n",
                v2c->signature->algid);
        }
        DBG(FIT_TRACE_INFO, "\nLicgen version = %d\n", v2c->lic.header.licgen_version);
        DBG(FIT_TRACE_INFO, "LM version = %d\n", v2c->lic.header.lm_version);
        if (v2c->lic.header.uid[0] != 0)
        {
            DBG(FIT_TRACE_INFO, "License UID : ");
            for (cntr=0; cntr<FIT_UID_LEN; cntr++)
                DBG(FIT_TRACE_INFO, "%X ", v2c->lic.header.uid[cntr]);
        }
#ifdef FIT_USE_NODE_LOCKING
        if (v2c->lic.header.licensefp.magic == 0x666D7446) /* 'fitF' */
        {
            DBG(FIT_TRACE_INFO, "Fingerprint information :");
            DBG(FIT_TRACE_INFO, " Algorithm = %X\n", v2c->lic.header.licensefp.algid);
            DBG(FIT_TRACE_INFO, "Fingerprint Hash :");
            for (cntr=0; cntr<FIT_DM_HASH_SIZE; cntr++)
                DBG(FIT_TRACE_INFO, "%X ", v2c->lic.header.licensefp.hash[cntr]);
        }
#endif /* ifdef FIT_USE_NODE_LOCKING */
        if (v2c->lic.cont != NULL)
        {
            DBG(FIT_TRACE_INFO, "\nLicense container ID = %ld\n", v2c->lic.cont->id);
            if (v2c->lic.cont->vendor != NULL)
            {
                DBG(FIT_TRACE_INFO, "\tVendor ID = %ld\n",
                    v2c->lic.cont->vendor->vendorid);
                DBG(FIT_TRACE_INFO, "\tProduct ID = %d\n",
                    v2c->lic.cont->vendor->prod.prodid);
                if (v2c->lic.cont->vendor->prod.prodpart != NULL)
                {
                    /* Get pointer to first product in the license */
                    fit_prodpart_data_t *prodpart = v2c->lic.cont->vendor->prod.prodpart;

                    while(prodpart != NULL)
                    {
                        /* Get pointer to first feature in the product */
                        fit_feature_data_t *featarray = prodpart->properties.feat;
                        DBG(FIT_TRACE_INFO, "\t\tProduct Part Information = %d\n",
                            prodpart->partid);

                        if (prodpart->properties.perpetual == 0)
                            DBG(FIT_TRACE_INFO, "\t\tIs License Perpetual = FALSE\n");
                        if (prodpart->properties.perpetual == 1)
                            DBG(FIT_TRACE_INFO, "\t\tIs License Perpetual = TRUE\n");
                        if (prodpart->properties.startdate != 0)
                            DBG(FIT_TRACE_INFO, "\t\tLicense Start Date = %lu\n",
                                prodpart->properties.startdate);
                        if (prodpart->properties.enddate != 0)
                            DBG(FIT_TRACE_INFO, "\t\tLicense End Date = %lu\n",
                                prodpart->properties.enddate);

                        while(featarray != NULL)
                        {
                            DBG(FIT_TRACE_INFO, "\t\t\tFeature ID = %lu\n", featarray->featid);
                            featarray = featarray->next;
                        }
                        prodpart = prodpart->next;
                    }
                }
            }
        }
    }
    DBG(FIT_TRACE_INFO, "*** End License Data ****************************************************\n");
}


uint16_t write_get_info_buffer(uint16_t *current_offset, uint16_t buffer_length,
                               uint8_t *buffer, const char *format, ...)
{
    va_list arg;

    if((buffer_length - *current_offset) < TEMP_BUF_LEN)
        return 0;

    va_start (arg, format);
    *current_offset += (uint16_t)vsprintf ((char*)buffer + *current_offset, format, arg);
    va_end (arg);

    return *current_offset;
}

/**
 *
 * fit_testgetinfodata_json
 *
 * This function retrieves license information in JSON format, using the get license info API. 
 *
 * @param IN    licenseData \n Pointer to license data for which information is
 *                             sought.
 *
 * @param OUT   pgetinfo    \n On return will contain the information sought in
 *                             form of string.
 *
 * @param OUT   getinfolen  \n On return this will contain length of data contained
 *                             in pgetinfo
 *
 */
fit_status_t fit_testgetinfodata_json(fit_pointer_t *licenseData,
                                 uint8_t *pgetinfo,
                                 uint16_t *getinfolen)
{
    fit_status_t status = FIT_STATUS_OK;
    uint16_t featcnt    = 0;
    uint16_t cntr       = 0;
    fit_v2c_data_t V2C;
    fit_product_data_t *products = NULL;
    fit_feature_data_t *features = NULL;
    fit_prodpart_data_t *prodpart = NULL;
    uint16_t offset     = 0;

    DBG(FIT_TRACE_INFO, "\nTest case:Get Info ---------\n");
    fit_memset((uint8_t*)&V2C, 0x0, sizeof(fit_v2c_data_t));

    if (licenseData->length==0) return FIT_STATUS_INVALID_V2C;

    if (pgetinfo == NULL || getinfolen <= 0)
        return FIT_STATUS_INSUFFICIENT_MEMORY;

    /* Parse license data and get requested license data */
    status = fit_licenf_get_info(licenseData, fit_getlicensedata_cb, &V2C);
    if (status != FIT_STATUS_OK)
    {
        *getinfolen = 0;
        freelicensedata(&V2C);
        return status;
    }

    if (!write_get_info_buffer(&offset, *getinfolen, pgetinfo, "{\n\"status\":\"0\",\n\"text\":\"FIT_STATUS_OK\",\n"))
    	goto end;

    if (status == FIT_STATUS_OK)
    {
        status = FIT_STATUS_OK;
        /* check the output against hard coded hard coded values */
        if(!write_get_info_buffer(&offset, *getinfolen, pgetinfo, "\"Licver\":\"%hd\",\n",
                V2C.lic.header.licgen_version))
            goto end;

        if(!write_get_info_buffer(&offset, *getinfolen, pgetinfo, "\"LMver\":\"%hd\",\n",
                V2C.lic.header.lm_version))
            goto end;

        if (V2C.lic.header.uid[0] != 0 && V2C.lic.header.uid[31] != 0)
        {
            if(!write_get_info_buffer(&offset, *getinfolen, pgetinfo, "\"UID\":\""))
                goto end;
            for (cntr = 0; cntr < 32; cntr++)
                if(!write_get_info_buffer(&offset, *getinfolen, pgetinfo, "%X",
                        V2C.lic.header.uid[cntr]))
                    goto end;
            if(!write_get_info_buffer(&offset, *getinfolen, pgetinfo, "\",\n"))
                goto end;
        }
#ifdef FIT_USE_NODE_LOCKING
        if (V2C.lic.header.licensefp.magic == 0x666D7446) /* 'fitF' */
        {
            if(!write_get_info_buffer(&offset, *getinfolen, pgetinfo, "\"HID\":\"%X\",\n",
                    V2C.lic.header.licensefp.algid))
                goto end;
/*
            if(!write_get_info_buffer(&offset, *getinfolen, pgetinfo, "\"FPHash\":\""))
                goto end;

            for (cntr=0; cntr<FIT_DM_HASH_SIZE; cntr++)
                if(!write_get_info_buffer(&offset, *getinfolen, pgetinfo, "%X ",
                        V2C.lic.header.licensefp.hash[cntr]))
                    goto end;

            if(!write_get_info_buffer(&offset, *getinfolen, pgetinfo, "\",\n"))
                goto end;
*/
        }
#endif /* ifdef FIT_USE_NODE_LOCKING */

        if (V2C.lic.cont == NULL)
            goto end;

        if(!write_get_info_buffer(&offset, *getinfolen, pgetinfo, "\"CID\":\"%ld\",\n",
                V2C.lic.cont->id))
            goto end;
        if (V2C.lic.cont->vendor == NULL)
            goto end;
        if(!write_get_info_buffer(&offset, *getinfolen, pgetinfo, "\"VID\":\"%ld\",\n",
                V2C.lic.cont->vendor->vendorid))
            goto end;

        /* Products information. */
        products = (fit_product_data_t *)&(V2C.lic.cont->vendor->prod);
        if (products == NULL)
            goto end;
        if(!write_get_info_buffer(&offset, *getinfolen, pgetinfo, "\"PID\":\"%ld\",\n",
                products->prodid))
            goto end;
        if (products->verregex[0] != 0 && products->verregex[1] != 0)
        {
            if(!write_get_info_buffer(&offset, *getinfolen, pgetinfo, "\"Ver_regex\":\"%s\",\n",
                    products->verregex))
                goto end;
        }

        prodpart = products->prodpart;
        if (!write_get_info_buffer(&offset, *getinfolen, pgetinfo, "\n\"PPARTS\":[\n"))
        	goto end;

        while (prodpart != NULL)
        {

            featcnt=0;
            if(!write_get_info_buffer(&offset, *getinfolen, pgetinfo, "{\"PPID\":\"%ld\",\n",
                    prodpart->partid))
                goto end;

            features = prodpart->properties.feat;
            while(features != NULL)
            {
                features = features->next;
                featcnt++;
            }

            if(!write_get_info_buffer(&offset, *getinfolen, pgetinfo, "\"FC\":\"%d\",\n", featcnt))
                goto end;

            features = prodpart->properties.feat;
            if(!write_get_info_buffer(&offset, *getinfolen, pgetinfo, "\"FID\":\""))
                goto end;
            while(features != NULL)
            {
                if(!write_get_info_buffer(&offset, *getinfolen, pgetinfo, "%ld,",
                        features->featid))
                    goto end;
                features= features->next;
            }


            if(!write_get_info_buffer(&offset, *getinfolen, pgetinfo, "\",\n"))
                goto end;
            if (prodpart->properties.perpetual)
                if(!write_get_info_buffer(&offset, *getinfolen, pgetinfo, "\"Perpetual\":\"%d\",\n",
                    prodpart->properties.perpetual))
                goto end;
            if (prodpart->properties.startdate)
                if(!write_get_info_buffer(&offset, *getinfolen, pgetinfo, "\"Start\":\"%lu\",\n",
                    prodpart->properties.startdate))
                goto end;
            if (prodpart->properties.enddate)
                if(!write_get_info_buffer(&offset, *getinfolen, pgetinfo, "\"End\":\"%lu\",\n",
                    prodpart->properties.enddate))
                goto end;
            if (!write_get_info_buffer(&offset, *getinfolen, pgetinfo, "},\n"))
            	goto end;

            prodpart = prodpart->next;
        }

        if (!write_get_info_buffer(&offset, *getinfolen, pgetinfo, "],\n"))
        	goto end;


        if (V2C.signature == NULL)
            goto end;
        if(!write_get_info_buffer(&offset, *getinfolen, pgetinfo, "\"AlgID\":\"%hd\",\n",
                V2C.signature->algid))
            goto end;
    }

    end:
    /* Print the license information */
    printlicensedata(&V2C);

    /* Free memory allocated in getting license information.*/
    freelicensedata(&V2C);
    *getinfolen = offset;

    return status;
}

