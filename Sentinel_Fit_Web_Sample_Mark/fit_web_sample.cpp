/****************************************************************************\
**
** fit_web_sample.cpp
**
** Sentinel Fit Web Sample
**
** Needs Energia_core and Energia_Ethernet projects
** (libs taken from the energia.nu package, see sources for copyrights)
**
** Copyright (C) 2016, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#define USE_STATIC_IP

#define FIRMWARE_VERSION "1.1.42"

/*  if USE_STATIC_IP is defined, the following addresses are used,
 *  else they are filled/owerwritten by DHCP
 *  (gateway and DNS are NOT used by this Fit Web Sample)
 */
char my_ip[64]       = "192.168.2.11";
char my_subnet[64]   = "255.255.255.0";
char my_gateway[64]  = "192.168.2.1";
char my_dns[64]      = "192.168.2.1";

char my_mac[64]      = "00-00-00-00-00-00";  /* will be read from Tiva ROM */

/********************************************************************************************/

#include <energia.h>
#include <stdarg.h>
#include <driverlib/eeprom.h>
#include <Ethernet.h>

#include "util.h"
#include "www.h"

#include "fit_config.h"
#include "fit.h"
#include "fit_debug.h"

#include "driverlib/sysctl.h"

/********************************************************************************************/

/* setup the Fit key array */

uint8_t no_of_keys = 2;
uint8_t no_of_alg = 1;  /* per key */

extern uint16_t aes_alg_guid;
extern uint16_t rsa_alg_guid;

uint8_t aesalglist_store[32];  /* currently  8 */
uint8_t rsaalglist_store[32];  /* currently  8 */
uint8_t key_arr_store[64];     /* currently 16 */

fit_algorithm_list_t *aesalglist = (fit_algorithm_list_t *)&aesalglist_store;
fit_algorithm_list_t *rsaalglist = (fit_algorithm_list_t *)&rsaalglist_store;
fit_key_array_t *key_arr = (fit_key_array_t *)&key_arr_store;

fit_key_data_t aes_key_data;
fit_key_data_t rsa_key_data;


#include "fit_internal.h"  /* fit_memset */

/**
 *  dump fit_key_array structure to console
 */
int dump_fit_key_array(fit_key_array_t *keys)
{
	int           i, j;
	uint8_t       num_of_alg;
	uint16_t      alg;
	fit_pointer_t fp;

	pr("\n");
    if ((unsigned int)&read_eeprom_u8 == (unsigned int)keys->read_byte)
    	pr("read_byte: read_eeprom_u8\n");
    else
    if ((unsigned int)&read_ram_u8 == (unsigned int)keys->read_byte)
    	pr("read_byte: read_ram_u8\n");
    else
    	pr("read_byte: UNKNOWN %lu\n", (unsigned int) keys->read_byte);
    pr("number_of_keys: %d\n", keys->number_of_keys);

    for (i=0; i<keys->number_of_keys; i++) {
    	pr("  key %d: %08X\n", i, (unsigned int) keys->keys[i]);
    	pr("    key       : %08X\n", (unsigned int)keys->keys[i]->key);

    	fp.data = keys->keys[i]->key;
    	fp.length = 16;
    	fp.read_byte = keys->read_byte;
    	fit_ptr_dump(&fp);

    	pr("    key_length: %d\n", keys->keys[i]->key_length);
    	num_of_alg = keys->keys[i]->algorithms->num_of_alg;
    	pr("    algorithms->num_of_alg: %d\n", num_of_alg);
    	for (j=0; j<num_of_alg; j++) {
    		alg = *(keys->keys[i]->algorithms->algorithm_guid[j]);
    		if (alg == 0x1001)
                pr("      algorithm_guid[%d]: %04X FIT_RSA_2048_ADM_PKCS_V15_ALG_ID\n", j, alg);
    		else if (alg == 0x1002)
                pr("      algorithm_guid[%d]: %04X FIT_AES_128_OMAC_ALG_ID\n", j, alg);
    		else
                pr("      algorithm_guid[%d]: %04X UNKNOWN\n", j, alg);
    	}
    }

	pr("\n");
	return 1; /* OK */
}

/********************************************************************************************/

/**
 * Set our global fit_key_array to use the RSA/AES keys from EEPROM
 */
void set_key_array (void)
{
	fit_pointer_t fp;

	aesalglist = (fit_algorithm_list_t *)&aesalglist_store;
	rsaalglist = (fit_algorithm_list_t *)&rsaalglist_store;
	key_arr = (fit_key_array_t *)&key_arr_store;

    fit_memset((uint8_t *)aesalglist, 0, sizeof (fit_algorithm_list_t) + no_of_alg*sizeof(uint16_t *));
    aesalglist->num_of_alg = no_of_alg;
    aesalglist->algorithm_guid[0] = &aes_alg_guid;

    set_fit_ptr_ee(&fp, EE_AES_OFFSET, EE_AES_MAXSIZE);
    aes_key_data.key = fp.data;
    aes_key_data.key_length = fp.length;
    aes_key_data.algorithms = aesalglist;


    fit_memset((uint8_t *)rsaalglist, 0, sizeof (fit_algorithm_list_t) + no_of_alg*sizeof(uint16_t *));
    rsaalglist->num_of_alg = no_of_alg;
    rsaalglist->algorithm_guid[0] = &rsa_alg_guid;

    set_fit_ptr_ee(&fp, EE_RSA_OFFSET, EE_RSA_MAXSIZE);
    rsa_key_data.key = fp.data;
    rsa_key_data.key_length = fp.length;
    rsa_key_data.algorithms = rsaalglist;


    key_arr->number_of_keys = no_of_keys;
    key_arr->keys[0] = (fit_key_data_t *)&aes_key_data;
    key_arr->keys[1] = (fit_key_data_t *)&rsa_key_data;
    key_arr->read_byte = (fit_read_byte_callback_t) read_eeprom_u8;

#if 0
    dump_fit_key_array(key_arr);
    set_fit_ptr_ee(&fitptrlic, EE_V2C_OFFSET, EE_V2C_MAXSIZE);
    status = fit_licenf_consume_license(&fitptrlic, 2, key_arr);
    pr("fit_licenf_consume_license() status: %d: %s\n", status, fit_get_error_str(status));

    dump_fit_key_array(&fit_keys);
    set_fit_ptr_ee(&fitptrlic, EE_V2C_OFFSET, EE_V2C_MAXSIZE);
    status = fit_licenf_consume_license(&fitptrlic, 2, &fit_keys);
    pr("fit_licenf_consume_license() status: %d: %s\n", status, fit_get_error_str(status));
#endif
}

/********************************************************************************************/

/**
 * consume a license using feature_id param and licenses/keys from EEPROM
 */
fit_status_t do_consume_license(uint16_t feature_id)
{
    fit_pointer_t fp = { 0 };
    fit_status_t status = FIT_STATUS_UNKNOWN_ERROR;

    set_key_array();
    set_fit_ptr_ee(&fp, EE_V2C_OFFSET, EE_V2C_MAXSIZE);
    status = fit_licenf_consume_license(&fp, feature_id, key_arr);
    pr("fit_licenf_consume_license(feature:%d) status: %d: %s\n", feature_id, status,
            fit_get_error_str(status));

    return status;
}

/********************************************************************************************/

/**
 * report some data about internet connection to console
 */

void printEthernetData()
{
    uint8_t mac[6];
    char s[64];

    Ethernet.macAddress(mac);
    sprintf(s, "%02X-%02X-%02X-%02X-%02X-%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    pr("\nMAC Address:      %s\n", s);

    IPAddress ip = Ethernet.localIP();
    pr("IP Address:       %s\n", iptoa(ip, s));

    IPAddress subnet = Ethernet.subnetMask();
    pr("NetMask:          %s\n", iptoa(subnet, s));

    IPAddress gateway = Ethernet.gatewayIP();
    pr("Gateway:          %s\n", iptoa(gateway, s));

    IPAddress dns = Ethernet.dnsServerIP();
    pr("DNS:              %s\n", iptoa(dns, s));
}

/********************************************************************************************/

/**
 * Arduino-sytle setup()
 * - init uart, leds, softclock etc. by fit_board_setup()
 * - init ethernet
 * - init web server
 */

char firmware_version[] = FIRMWARE_VERSION;

void setup()
{
    fit_board_setup(); /* also inits UART, clock and LED(s) */
    pr("\n\n\n\n=============================================\n"
               " Sentinel Fit Web Demo %s\n"
               "=============================================\n", firmware_version);

    Ethernet.enableLinkLed();
    Ethernet.enableActivityLed();

    // Start Ethernet with the build in MAC Address
    pr("\nConnecting to Ethernet....\n");
    get_mac_address(my_mac);
    pr("  MAC Address (ROM): %s\r\n", my_mac);

#ifdef USE_STATIC_IP
    pr("  setting static IP address: %s\n", my_ip);
    Ethernet.begin(0, atoip(my_ip), atoip(my_dns), atoip(my_gateway), atoip(my_subnet));
#else
    pr("  getting IP address via DHCP\n");
    if (Ethernet.begin(0) == 0) {
        pr("Failed to configure Ethernet using DHCP\n");
        while (1) {}
    }
    sprintf(my_ip, "%u.%u.%u.%u",
            Ethernet.localIP()[0],
            Ethernet.localIP()[1],
            Ethernet.localIP()[2],
            Ethernet.localIP()[3]);
#endif

    www_server_init();
//  ntp_client_init();
    printEthernetData();
    //MAH
	//
	// Enable the GPIO port that is used for the on-board LED.
	//
		SysCtlPeripheralEnable(SYSCTL_PERIPH_GPION);

		//
		// Check if the peripheral access is enabled.
		//
		while(!SysCtlPeripheralReady(SYSCTL_PERIPH_GPION))
		{
		}

		//
		// Enable the GPIO pin for the LEDs (PN0 & PN1).  Set the direction as output, and
		// enable the GPIO pin for digital function.
		//
		GPIOPinTypeGPIOOutput(GPIO_PORTN_BASE, GPIO_PIN_0);
        GPIOPinTypeGPIOOutput(GPIO_PORTN_BASE, GPIO_PIN_1);
		// Turn off the LED.
		//
		GPIOPinWrite(GPIO_PORTN_BASE, GPIO_PIN_0, 0x0);
        GPIOPinWrite(GPIO_PORTN_BASE, GPIO_PIN_1, 0x0);
    //MAH

    pr("\r\nEE size: %d\n", EEPROMSizeGet());

    /* notify user about IP address */
    pr("\r\n"
       "------------------------------------------------------\r\n"
       "  Browse to:\r\n");
    pr("    http://%s/\r\n", my_ip);
    pr("------------------------------------------------------\r\n");
} /* setup */

/********************************************************************************************/

/**
 * Arduino-sytle loop()
 *   (we are just a web server ...)
 */
void loop()
{
    do_www();
}

/********************************************************************************************/

