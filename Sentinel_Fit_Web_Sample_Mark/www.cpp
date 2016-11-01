/****************************************************************************\
**
** www.cpp
**
** Generates web pages for Sentinel Fit web demo
**
** Copyright (C) 2016, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#include "www.h"
#include "www_inc.h"
#include "driverlib/sysctl.h"

EthernetClient www;
EthernetServer server(80);

//MAH
	int toggleLed1, toggleLed2 = 0; //1 = Green; 2 = Blue
//MAH


/********************************************************************************************/

/**
 * reply 404 page not found header and content
 */

void print404()
{
    www.print("HTTP/1.1 404 Not Found\r\n"
              "Content-type:text/plain\r\n"
              "\r\n"
              "Sentinel Fit Web Demo\r\n"
              "404 Page Not Found\r\n"
              "\r\n");
}

/**
 * reply <hr>, Back button, and end-of-page
 */

void print_end_of_page(void)
{
    www.println("<br><hr><br>"
                "&nbsp;<a href=\"/\">Back</a>"
                "</body></html>");
}

/********************************************************************************************/

/**
 * send a plain text http header
 */
void print_200_plain (void)
{
    www.print("HTTP/1.1 200 OK\r\n"
              "Access-Control-Allow-Origin: *\r\n"
              "Content-type:text/plain\r\n"
              "\r\n");
}

/**
 * send an html http header plus html header with CCS and JS
 */

void print_http_head(int script)
{
    www.print("HTTP/1.1 200 OK\r\n"
              "Content-type:text/html\r\n"
              "\r\n"
              "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\">\r\n"
              "<html>"
              "<head>\r\n");

    www.println("<title>Sentinel Fit Demo</title>");
    www.println(www_style);
    if (script)
        www.println(www_script);
    www.println("</head>");
}

/**
 * send page title (prog name, logo)
 */
void print_http_title()
{
    www.println(
        "<table class=\"nob\" width=\"100%\">"
        "<tr><td  class=\"nob\"valign=\"bottom\"><font size=\"+3\"><font color=\"#ba0f6b\">"
        "Sentinel Fit Web Demo</font></font></td>"
        "<td align=\"right\" class=\"nob\"><img src=\"gemalto.png\"></td></tr>"
        "</table>"
        "<hr>"
        "<br>");
}

/***********************************************************************************************************/

/**
 * license validation with caching
 */

int          validation_cache_ok = 0;
fit_status_t validation_cache    = FIT_STATUS_LIC_CACHING_ERROR;

void validation_cache_invalidate (void)
{
    validation_cache_ok = 0;
    validation_cache = FIT_STATUS_LIC_CACHING_ERROR;
    fit_led_off();
}

fit_status_t validate_license_ee (void)
{
    fit_pointer_t lic = {0};
    unsigned long tm;
    fit_status_t  status;

    if (validation_cache_ok)
        goto cache_ok;

    set_fit_ptr_ee(&lic, EE_V2C_OFFSET, EE_V2C_MAXSIZE);
    if (lic.length < 1) {
        validation_cache_ok = 0;
        validation_cache = FIT_STATUS_INVALID_V2C;
        return validation_cache;
    }

    tm = millis();
    set_key_array();
    fit_trace_flags = 0;
    status = fit_licenf_validate_license(&lic, key_arr);
    tm = millis() - tm;
    pr("re-validate: %d %s (%d ms)\n", status, fit_get_error_str(status), tm);

    validation_cache = status;
    validation_cache_ok = 1;

cache_ok:
/*
    if (FIT_STATUS_OK == validation_cache)
        fit_led_on();
    else
        fit_led_off();
*/
    return validation_cache;
}

fit_status_t validate_license_ee_new (void)
{
    validation_cache_invalidate();
    return validate_license_ee();
}

/***********************************************************************************************************/

/**
 * send get_info information in JSON format
 */

uint8_t getinfojson[4096];

void print_getinfo_json()
{
    uint16_t getinfolen = sizeof(getinfojson);
    fit_pointer_t fitptrlic = {0};
    fit_status_t     status   = FIT_STATUS_OK;
    fit_status_t     valid_status;

    set_fit_ptr_ee(&fitptrlic, EE_V2C_OFFSET, EE_V2C_MAXSIZE);

    fit_trace_flags = 0; //FMT_TRACE_ALL;
    status = fit_testgetinfodata_json(&fitptrlic, getinfojson, &getinfolen);
    pr("getinfo json status=%d, size=%d\n", status, getinfolen);

    valid_status = validate_license_ee();

    print_200_plain();

    if (status==FIT_STATUS_OK) {
        www.print((char*)&getinfojson);
        www.print("\"validate\":\"");
        www.print(valid_status);
        www.print("\",\r\n\"vtext\":\"");
        www.print(fit_get_error_str(valid_status));
        www.print("\",\r\n\"time\":\"");
        www.print(fit_time_get());
        www.println("\"\r\n}\r\n");
    } else {
        www.print("{\"status\":\"");
        www.print(status);
        www.print("\",\r\n\"text\":\"");
        www.print(fit_get_error_str(status));
        www.print("\"\r\n}\r\n");
    }
}

/***********************************************************************************************************/

int get_xml_fingerprint(char *xml, size_t xml_max_size);
void fit_ptr_dump_www_8(fit_pointer_t *fp);

/***********************************************************************************************************/

/**
 * the main page
 */
void print_getinfo()
{
    char s[1024];
    fit_pointer_t fp;

    print_http_head(1);
    www.println("<body onload=\"settime()\">");
    print_http_title();
    www.println("<div id=\"xx\">Connecting ...</div>"
                "<br><hr><br>");

    www.println(www_form);

    s[0] = 0;
    www.println("<br><hr><br><table class=\"sml\"><tr class=\"sml\">"
                "<td><a href=\"/dump.html\">Show EEPROM</a></td>"
                "<td><table class=\"sml\"><tr class=\"sml\">"
                "<td>fit_config.h:</td><td>");

    /* show settings from fit_config.h on main page */
#ifdef FIT_USE_RSA_SIGNING
    strcat(s, "#define FIT_USE_RSA_SIGNING<br>");
#endif
#ifdef FIT_USE_PEM
    strcat(s, "#define FIT_USE_PEM<br>");
#endif
#ifdef FIT_USE_AES_SIGNING
    strcat(s, "#define FIT_USE_AES_SIGNING<br>");
#endif
#ifdef FIT_USE_CLOCK
    strcat(s, "#define FIT_USE_CLOCK<br>");
#endif
#ifdef FIT_USE_NODE_LOCKING
    strcat(s, "#define FIT_USE_NODE_LOCKING<br>");
#endif
#ifdef FIT_USE_DEBUG_MSG
    strcat(s, "#define FIT_USE_DEBUG_MSG<br>");
#endif

    www.print(s);
    www.println("</td></tr></table>"
                "</td><td>");

    /* show device_id and resulting fingerprint */
    {
        char *devid;
        char id[255];
        char fp[256];
        uint16_t len = sizeof(id) - 1;
        int st;
        fit_status_t status;

        status = fit_device_id_get((uint8_t*) &id, sizeof(id), &len);
        if (FIT_STATUS_OK != status) {
            strcpy(id, fit_get_error_str(status));
            len = strlen(id);
        }
        id[len] = 0;
        devid = (char*) &id;

        st = get_xml_fingerprint(fp, sizeof(fp));
        if (st)
            strcpy(fp, "ERROR");

        www.println("<table class=\"sml\"><tr class=\"sml\"><td>fit_device_id_get()</td><td>");
        www.println(devid);
        www.print("</td></tr><tr><td>Fingerprint:</td><td>");
        www.print(fp);
        www.println("</td></tr></table>");
    }

    www.println("</td></tr></table>\r\n"
                "<script>");

    www.print("document.getElementById(\"v2c\").innerHTML=\"");
    set_fit_ptr_ee(&fp, EE_V2C_OFFSET, EE_V2C_MAXSIZE);
    fit_ptr_dump_www_8(&fp);

    www.print("\";document.getElementById(\"rsa\").innerHTML=\"");
    set_fit_ptr_ee(&fp, EE_RSA_OFFSET, EE_RSA_MAXSIZE);
    fit_ptr_dump_www_8(&fp);

    www.print("\";document.getElementById(\"aes\").innerHTML=\"");
    set_fit_ptr_ee(&fp, EE_AES_OFFSET, EE_AES_MAXSIZE);
    fit_ptr_dump_www_8(&fp);
    www.println("\";");

    www.println("</script>\r\n"
                "</body></html>");
}

/***********************************************************************************************************/

EXTERNC fit_status_t fit_get_device_fpblob(fit_fingerprint_t* fp,
                   fit_fp_callback callback_fn);

EXTERNC int mbedtls_base64_encode( unsigned char *dst, size_t dlen, size_t *olen,
                   const unsigned char *src, size_t slen );


typedef struct my_fit_fingerprint {
    uint32_t    magic;
    uint32_t    algid;
    uint8_t     hash[FIT_DM_HASH_SIZE];
} my_fit_fingerprint_t;

int get_xml_fingerprint(char *xml, size_t xml_max_size)
{
    fit_fingerprint_t fp = { 0 };
    my_fit_fingerprint_t my_fp;
    unsigned char b64[256];
    int st;
    size_t b64len = 0;
    fit_status_t status;

    memset(&b64, 0, sizeof(b64)); /* assure ending 0 */

    status = fit_get_device_fpblob(&fp, FIT_DEVICE_ID_GET);
    if (FIT_STATUS_OK != status) {
        pr("fit_get_device_blob() ERROR %d %s\n", status, fit_get_error_str(status));
        return 1;
    }

    /* copy to my_fp for correct transport alignment */
    memset(&my_fp, 0, sizeof(my_fp)); /* assure ending 0 */
    my_fp.magic = fp.magic;
    my_fp.algid = fp.algid;
    memcpy(my_fp.hash, fp.hash, FIT_DM_HASH_SIZE);

    st = mbedtls_base64_encode(b64, sizeof(b64) - 2,
            &b64len,
            (const unsigned char *) &my_fp, sizeof(my_fp));
    if (st) {
        pr("mbedtls_base64_encode() ERROR %d %08X <br>", st, st);
        return 1;
    }

    if ((b64len > 0) && (b64len < xml_max_size)) {
        strcpy(xml, (char*) &b64);
        return 0;
    }

    return 1;
}

void print_fingerprint()
{
    fit_status_t status = FIT_STATUS_OK;
    char fp[256];
    int st;
    char *xx;
    uint8_t id[255];
    uint16_t len = sizeof(id) - 1;

    print_200_plain();

    www.println();
    www.print("<DeviceID>");

    status = fit_device_id_get(id, sizeof(id), &len);
    xx = (char*) &id;
    if (status == FIT_STATUS_OK) {
        id[len] = 0;
    } else {
        sprintf(xx, "fit_device_id_get() ERROR %d %s\n", status, fit_get_error_str(status));
    }
    www.print(xx);
    www.println("</DeviceID>");

    www.print("<fingerprint>");
    st = get_xml_fingerprint(fp, sizeof(fp));
    if (st) {
        www.print("ERROR reading/generating fingerprint");
    } else {
        www.print(fp);
    }
    www.println("</fingerprint>");
    www.println();
}

/***********************************************************************************************************/

void do_cmd(char *cmd, char* result)
{
    char *arg;
    char s[256];

    strcpy(result, "ERROR");

    arg = strchr(cmd, '=');
    if (!arg) {
        strcpy(result, "Missing \"=\" in argument.");
        return;
    }

    *arg = 0;
    arg++;

    //  www.print("cmd: \""); www.print(cmd); www.println("\"");
    //  www.print("arg: \""); www.print(arg); www.println("\"");

    if (strcasecmp(cmd, "unixtime") == 0) {
        uint32_t u = atol(arg);

        fit_time_set(u);
        u = fit_time_get();
        pr("unixtime set to %lu\r\n", u);
    }
    else
    if ((strcasecmp(cmd, "featureid") == 0) || (strcasecmp(cmd, "fid") == 0)) {
        fit_status_t status = FIT_STATUS_OK;
        uint32_t u = atol(arg);
        char color[10];

        status = do_consume_license(u);

        if (status == FIT_STATUS_OK)
			strcpy(color, "#00C000");
        else
            strcpy(color, "#FF0000");

        www.print("<table><tr><td class=\"nob\">calling function</td><td class=\"nob\">status = fit_licenf_consume_license(&license, ");
        snprintf(s, sizeof(s), "<b>%u</b>, &key_array)</td></tr>\n", (unsigned int) u);
        www.print(s);
        snprintf(s, sizeof(s),
                "<tr><td class=\"nob\">status</td><td class=\"nob\"><font color=\"%s\">%d</font></td></tr>\n",
                color, status);
        www.print(s);
        snprintf(s, sizeof(s),
                "<tr><td class=\"nob\">fit_get_error_str(%d)</td><td class=\"nob\"><font color=\"%s\">%s</font></td></tr>\n",
                status, color, fit_get_error_str(status));
        www.print(s);
        www.println("</table>"
                    "<br><hr><br>&nbsp;<a href=\"/\">Back</a>");
    }
    else
    	if (strcasecmp(cmd, "unixtime") == 0)

    strcpy(result, "\r\nOK\r\n");
}

/***********************************************************************************************************/

void get_set(const char *line)
{
    char arg[128];
    char result[128];
    char *cmd = NULL;
    char *end_args;

    result[0] = 0;

    print_200_plain();

    strncpy(arg, line, sizeof(arg));
    pr("set: \"%s\"\n", arg);

    if (strstr(arg, "GET /set?") == arg) {
        cmd = arg + 9;
        end_args = strstr(cmd, " HTTP");
        if (end_args) {
            *end_args = 0;
            do_cmd(cmd, result);
        }
    }

    if (result[0] == 0) {
        www.println("unknown \"set\" command.<br>");
        if (cmd) {
            www.println(cmd);
        }
    } else {
        www.print(result);
    }
}

/***********************************************************************************************************/

void get_consume(const char *line)
{
    char arg[128];
    char result[128];
    char *cmd;
    char *end_args;

    result[0] = 0;
    cmd       = NULL;

    print_http_head(0);
    www.println("<body>");
    print_http_title();

    strncpy(arg, line, sizeof(arg));
    // pr("set: \"%s\"\n", arg);

    if (strstr(arg, "GET /consume?") == arg) {
        cmd = arg + 13;
        end_args = strstr(cmd, " HTTP");
        if (end_args) {
            *end_args = 0;
            do_cmd(cmd, result);
        }
    }

    if (result[0] == 0) {
        www.println("unknown \"set\" command.<br>");
        if (cmd) www.println(cmd);
    }

    www.println("</body></html>");
}

/***********************************************************************************************************/
void ledtoggle(int led)
{
    fit_status_t status = FIT_STATUS_OK;
    char s[256], color[10];


	pr("Toggle LED%d\n", led);

    print_http_head(0);
    www.println("<body>");
    print_http_title();

    status = do_consume_license(led+110); //Feature 111 = LED1 ("Green"; GPIO_PIN_1), Feature 112 = LED2 ("Blue"; GPIO_PIN_0)

    if (status == FIT_STATUS_OK) {
		strcpy(color, "#00C000"); //Green color
    	pr("LED%d Toggle Authorized\n", led);
    	if (led == 1)
    	{
            if (toggleLed1 == 0) {
                //
                // Turn on the LED.
                //
                GPIOPinWrite(GPIO_PORTN_BASE, GPIO_PIN_1, GPIO_PIN_1);
                toggleLed1 = 1;
            }
            else {
                //
                // Turn off the LED.
                //
                GPIOPinWrite(GPIO_PORTN_BASE, GPIO_PIN_1, 0x0);
                toggleLed1 = 0;
            }
        }
    	else
    	{
            if (toggleLed2 == 0) {
                //
                // Turn on the LED.
                //
                GPIOPinWrite(GPIO_PORTN_BASE, GPIO_PIN_0, GPIO_PIN_0);
                toggleLed2 = 1;
            }
            else {
                //
                // Turn off the LED.
                //
                GPIOPinWrite(GPIO_PORTN_BASE, GPIO_PIN_0, 0x0);
                toggleLed2 = 0;
            }
    	}
        snprintf(s, sizeof(s),
                "<tr><font color=\"%s\"><font size=\"+3\"><td class=\"nob\">You are authorized to toggle this LED"
                "</td></tr>\n", color);
        www.print(s);
    }
    else {
        strcpy(color, "#FF0000"); //Red color
    	pr("LED%d Toggle Unauthorized\n", led);
        snprintf(s, sizeof(s),
                "<tr><font color=\"%s\"><font size=\"+3\"><td class=\"nob\">You are not authorized to toggle this LED"
                "</td></tr>\n", color);
        www.print(s);
    }


    www.println("</body></html>");
    print_end_of_page();
}


/***********************************************************************************************************/
void fit_ptr_dump_www_8(fit_pointer_t *fp)
{
    uint8_t b;
    int i, len;
    uint8_t *data;
    char s[64];

    len = fp->length;
    if (len <= 0) {
        www.print("currently EMPTY");
    } else {
        sprintf(s, "current: %d bytes [", len);
        www.print(s);

        if (len > 8)
            len = 20;
        data = fp->data;
        for (i = 0; i < len; i++) {
            b = fp->read_byte(data++);
            sprintf(s, "%02X ", b);
            www.print(s);
        }
        if (len < fp->length) {
            www.print("...]");
        } else {
            www.print("]");
        }
    }
}

/***********************************************************************************************************/

void fit_ptr_dump_www(fit_pointer_t *fp, const char *name)
{
    uint8_t b;
    int i, col;
    uint8_t *data;
    char s[128];
    char hex[64];

    if (name) {
        if (*name) {
            sprintf(s, "%s  (Size: %d bytes)\r\n", name, fp->length);
            www.print(s);
        }
    }

    col = 0;
    data = fp->data;
    hex[0] = 0;
    sprintf(s, "%08X: ", 0);
    www.print(s);

    for (i = 0; i < fp->length; i++) {

        b = fp->read_byte(data);
        sprintf(s, "%02X ", b);
        www.print(s);
        data++;

        if ((b < 32) || (b > 126) || (b == '<') || (b == '>') || (b == '&'))
            hex[col] = '.';
        else
            hex[col] = b;
        hex[col + 1] = 0;

        if (++col > 15) {
            sprintf(s, "  %s\r\n%08X: ", hex, i);
            www.print(s);
            col = 0;
        }
    }
    if (col) {
        for (i = col; i < 16; i++)
            www.print("   ");
        www.print("  ");
        www.print(hex);
    }
    www.print("\r\n\r\n");
}

/***********************************************************************************************************/

void dump_v2c_and_keys()
{
    fit_pointer_t fp;

    print_200_plain();

    set_fit_ptr_ee(&fp, EE_V2C_OFFSET, EE_V2C_MAXSIZE);
    fit_ptr_dump_www(&fp, "V2C");

    set_fit_ptr_ee(&fp, EE_RSA_OFFSET, EE_RSA_MAXSIZE);
    fit_ptr_dump_www(&fp, "RSA pubkey");

    set_fit_ptr_ee(&fp, EE_AES_OFFSET, EE_AES_MAXSIZE);
    fit_ptr_dump_www(&fp, "AES key");
}


/***********************************************************************************************************/

extern char firmware_version[];

void dump_v2c_and_keys_html()
{
    fit_pointer_t fp;

    print_http_head(0);
    www.println("<body>");
    print_http_title();

    www.print("<div class=\"up\"><pre>");

    set_fit_ptr_ee(&fp, EE_V2C_OFFSET, EE_V2C_MAXSIZE);
    fit_ptr_dump_www(&fp, "V2C");

    set_fit_ptr_ee(&fp, EE_RSA_OFFSET, EE_RSA_MAXSIZE);
    fit_ptr_dump_www(&fp, "RSA pubkey");

    set_fit_ptr_ee(&fp, EE_AES_OFFSET, EE_AES_MAXSIZE);
    fit_ptr_dump_www(&fp, "AES key");

    www.print("<tr><td>Firmware ");
    www.print(firmware_version);
    www.println(" (" __DATE__ ", " __TIME__ ")</td></tr>"
                "</pre></div>"
                "<hr><br>"
                "&nbsp;<a href=\"/\">Back</a>"
                "</body></html>");
}


/***********************************************************************************************************/

#include "logo_png.h"

void get_logo()
{
    www.print("HTTP/1.1 200 OK\r\n"
              "Content-type:image/png\r\n"
              "Content-Length:");
    www.print(sizeof(logo_png));
    www.print("\r\n\r\n");

    www.write((const uint8_t*)logo_png, sizeof(logo_png));
}

/***********************************************************************************************************/

char *get_html_fit_status(char *buf, int size, fit_status_t status)
{
    if (status != FIT_STATUS_OK) {
        snprintf(buf, size, "<font color=\"FF0000\">%d %s</font>", status, fit_get_error_str(status));
    } else {
        snprintf(buf, size, "%d %s", status, fit_get_error_str(status));
    }
    return buf;
}

/***********************************************************************************************************/

/**
 * send msg inside a div, divclass 0 for error, else ok
 * also print msg to console
 */

void pr_www_div(int divclass, const char *msg)
{
    pr(msg);
    pr("\n");

    if (divclass) {
        www.print("<div class=\"up1\">");
    } else {
        www.print("<div class=\"up0\">");
    }
    www.print(msg);
    www.println("</div>");
}

/***********************************************************************************************************/

#include "mbedtls/pk.h"

fit_status_t validate_rsa_key(char *data_start, int data_len)
{
    fit_status_t status = FIT_STATUS_INVALID_RSA_PUBKEY;
    int ret;
    mbedtls_pk_context pk;

    pr("validate_rsa_key()\n");
    mbedtls_pk_init(&pk);

    ret = mbedtls_pk_parse_public_key(&pk, (const unsigned char *) data_start, data_len + 1);
    if (ret) {
        pr("[fit_validate_rsa_signature] parsing public key FAILED -0x%04x\n", -ret);
        status = FIT_STATUS_INVALID_RSA_PUBKEY;
    } else {
        status = FIT_STATUS_OK;
    }

    mbedtls_pk_free(&pk);
    return status;
}

/***********************************************************************************************************/

/**
 * POST handling for V2C/RSA/AES
 * multipart mime
 */
#define POST_FILE_V2C 1
#define POST_FILE_RSA 2
#define POST_FILE_AES 3

#define POST_BUFFER_SIZE (6 * 1024)

char post_header[POST_BUFFER_SIZE + 16];

void post_file(uint8_t filetype)
{
    char *s;
    int index, length = 0;
    unsigned long timeout;
    int i, data_length = 0;
    char c;
    char tmp[256];
    char boundary[256];
    char *data_start = NULL;
    char *data_stop = NULL;
    fit_status_t status = FIT_STATUS_INVALID_V2C;
    fit_pointer_t fp = { 0 };

    print_http_head(0);
    www.println("<body>");
    print_http_title();

    www.println("<div class=\"upb\">Received ");
    switch (filetype) {
    case POST_FILE_V2C:
        www.println("V2C");
        break;
    case POST_FILE_RSA:
        www.println("RSA public key");
        break;
    case POST_FILE_AES:
        www.println("AES key");
        break;
    default:
        www.print("unknown filetype: ");
        www.print(filetype);
        www.println("</div>");
        goto bail;
    }
    www.println("</div>");

    memset(post_header, 0, sizeof(post_header));

    index = 0;
    for (i = 0; i < POST_BUFFER_SIZE; i++) {
        c = www.read();
        post_header[index++] = c;

        if ((strstr(post_header, "\n\n")) ||
            (strstr(post_header, "\r\r")) ||
            (strstr(post_header, "\r\n\r\n")) ||
            (strstr(post_header, "\n\r\n\r")))
            break;
    }

    /* detect mime boundary */
    s = strstr(post_header, "Content-Type:");
    if (!s) {
        pr_www_div(0, "Content-Type not found");
        goto bail;
    }

    s = strstr(post_header, "boundary=");
    if (!s) {
        pr_www_div(0, "\"boundary=\" not found");
        goto bail;
    }

    s += 9; // skip "boundary="
    boundary[0] = 0;
    for (i = 0; i < 250; i++) {
        if (*s == '\n')
            break;
        if (*s == '\r')
            break;
        boundary[i] = *s;
        s++;
        boundary[i + 1] = 0;
    }

    pr("Boundary: \"%s\"\n", boundary);

    /* detect content length */
    s = strstr(post_header, "Content-Length:");
    length = 0;
    if (s)
        length = atoi(s + 15);
    pr("v2c length: %d\n", length);

    // read data
    index = 0;
    timeout = millis() + 1000;
    for (i = 0; i < length; i++) {
        while (www.available() <= 0) {
            if (timeout < millis())
                break;
        }
        c = www.read();
        if (index < POST_BUFFER_SIZE)
            post_header[index++] = c;
    }

    if (length < 2) {
        snprintf(tmp, sizeof(tmp), "Received data too small (%d)", length);
        www.print("<br>");
        pr_www_div(0, tmp);
        goto bail;
    }

    if (length > POST_BUFFER_SIZE) {
        snprintf(tmp, sizeof(tmp), "Received data too big (is: %d, max: %d)",
                length, POST_BUFFER_SIZE);
        www.print("<br>");
        pr_www_div(0, tmp);
        goto bail;
    }

    /* Extract data:
     *   - boundary
     *   - \n\r\n\r
     */

    s = strstr(post_header, boundary);
    if (!s) {
        pr_www_div(0, "First boundary not found");
        goto bail;
    }
    s++;
    s = strstr(s, "\r\n\r\n");
    if (!s) {
        pr_www_div(0, "Boundary local header not found");
        goto bail;
    }
    data_start = s + 4;
    pr("Start: %d\r\n", data_start - post_header);

    data_stop = strstr(data_start, boundary);
    data_stop = (char*) memmem(data_start, length - (data_start - post_header), boundary, strlen(boundary));
    if (!data_stop) {
        pr_www_div(0, "2nd boundary not found");
        goto bail;
    }

    pr("Stop: %d\r\n", data_stop - post_header);

    data_length = data_stop - data_start - 4; // "\r\n--"

    // dump data to http reply
    www.print("<div class=\"up\"><pre>");
    if (data_length <= 0) {
        www.print("(EMPTY)");
    } else {
        www.print(data_length);
        www.println(" bytes");
        set_fit_ptr_ram(&fp, (uint8_t *) data_start, data_length);
        fit_ptr_dump_www(&fp, NULL);
    }
    www.println("</pre></div>");

    /*-------------------------------------------------------------------------------------------------------------*/

    if (filetype == POST_FILE_V2C) {

        // validate received V2C
        if (data_length >= EE_V2C_MAXSIZE - 4) {
            snprintf(tmp, sizeof(tmp), "Received V2C too big: is %d, max %d", data_length, EE_V2C_MAXSIZE - 4);
            pr_www_div(0, tmp);
            goto bail;
        }

        set_fit_ptr_ram(&fp, (uint8_t *) data_start, data_length);
        fit_trace_flags = 0;
        status = FIT_STATUS_OK;
        set_key_array();

        if (data_length > 0) {
            status = fit_licenf_validate_license(&fp, key_arr);

            get_html_fit_status(tmp, sizeof(tmp), status);
            pr("fit_licenf_validate_license(): %s\n", tmp);

            if (status) {
                www.print("<div class=\"up0\">");
            } else {
                www.print("<div class=\"up1\">");
            }
            www.print("fit_licenf_validate_license(): ");
            www.print(tmp);
            www.println("</div>");

            if (FIT_STATUS_KEY_NOT_PRESENT == status) {
                www.println("<div class=\"up0\">You must upload an appropriate key (AES or RSA Public) "
                            "before you can consume licenses from this V2C.</div>");
            }

            // write V2C to EEPROM
            blob_write_ee(EE_V2C_OFFSET, EE_V2C_MAXSIZE, data_start, data_length);
            validate_license_ee_new(); /* do an uncached validate and set LED */
            www.println("<br><div class=\"upb\">License stored into EEPROM</div>");
        } else {
            /* Empty License */
            blob_write_ee(EE_V2C_OFFSET, EE_V2C_MAXSIZE, data_start, 0);
            www.println("<div class=\"upb\">Existing license was removed from EEPROM</div>");
            validate_license_ee_new();
        }
    }

    /*-------------------------------------------------------------------------------------------------------------*/

    if (filetype == POST_FILE_RSA) {

        // validate received RSA pubkey
        if (data_length >= EE_RSA_MAXSIZE - 4) {
            snprintf(tmp, sizeof(tmp), "RSA pubkey too big: is %d, max %d <br>", data_length, EE_RSA_MAXSIZE - 4);
            pr_www_div(0, tmp);
            goto bail;
        }

        /*  insert RSA public key validation */
        status = FIT_STATUS_OK;

        /* patch a 0 after RSA key to make mbedtls PEM parser happy */
        *(data_start + data_length) = 0;

        status = validate_rsa_key(data_start, data_length);
        snprintf(tmp, sizeof(tmp), "Validating received RSA pubkey: %d %s\n", status,
                fit_get_error_str(status));
        pr_www_div((FIT_STATUS_OK == status), tmp);

        // write RSA pubkey to EEPROM
        blob_write_ee(EE_RSA_OFFSET, EE_RSA_MAXSIZE, data_start, data_length);
        validate_license_ee_new(); /* do an uncached validate and set LED */
        www.println("<br><div class=\"upb\">RSA public key stored into EEPROM</div>");
    }

    /*-------------------------------------------------------------------------------------------------------------*/

    if (filetype == POST_FILE_AES) {

        // validate received AES key
        if (data_length >= EE_AES_MAXSIZE - 4) {
            snprintf(tmp, sizeof(tmp), "AES key too big: is %d, max %d", data_length, EE_AES_MAXSIZE - 4);
            pr_www_div(0, tmp);
            goto bail;
        }

        /*  insert AES key validation */
        status = FIT_STATUS_OK;

        // write AES key to EEPROM
        blob_write_ee(EE_AES_OFFSET, EE_AES_MAXSIZE, data_start, data_length);
        validate_license_ee_new(); /* do an uncached validate and set LED */
        www.println("<br><div class=\"upb\">AES key stored into EEPROM</div>");
    }

    /*-------------------------------------------------------------------------------------------------------------*/

bail:
    memset(post_header, 0, sizeof(post_header));
    print_end_of_page();
}

/***********************************************************************************************************/

void erase_ee(void)
{
    fit_pointer_t fp;

    print_http_head(0);
    www.println("<body>");
    print_http_title();

    www.print("<table><tr><td>"
              "EEPROM size</td><td>");
    www.print(EEPROMSizeGet());
    www.println("</td></tr>");

    www.println("<tr><td colspan=\"2\"><b><font color=\"#FF0000\">Performing an EEPROM mass erase ...</font></b></td></tr>");
    EEPROMMassErase();
    validate_license_ee_new();

    set_fit_ptr_ee(&fp, EE_V2C_OFFSET, EE_V2C_MAXSIZE);
    if (!fp.length) www.print("<tr><td>V2C</td><td>EMPTY</td></tr>");

    set_fit_ptr_ee(&fp, EE_RSA_OFFSET, EE_RSA_MAXSIZE);
    if (!fp.length) www.print("<tr><td>RSA pubkey</td><td>EMPTY</td></tr>");

    set_fit_ptr_ee(&fp, EE_AES_OFFSET, EE_AES_MAXSIZE);
    if (!fp.length) www.print("<tr><td>AES key</td><td>EMPTY</td></tr>");

    www.print("</table>");
    print_end_of_page();
}

/***********************************************************************************************************/

void do_www(void)
{

	www = server.available();
    if (www) {
        String currentLine = "";               // incoming data from the client
        boolean newConnection = true;
        uint32_t connectionActiveTimer = 0;    // connection start time

        pr("%u ", fit_time_get());
        // pr("port %d ", www.port());

        while (www.connected()) {
            if (newConnection) {
                connectionActiveTimer = millis();
                newConnection = false;
            }
            if (!newConnection && connectionActiveTimer + 1000 < millis()) {
                // if this while loop is still active 1000ms after a web client connected,
                // something is wrong - drop connection end exit
                goto www_done;
            }

            while (www.available()) {             // if there's bytes to read from the client,


            	char c = www.read();             // read a byte, then

                if ((c == '\n') || (c == '\r')) {                    // if the byte is a newline character

                    pr("Web request: <%s>\n", currentLine.c_str());

                    if (currentLine.startsWith("GET /getinfo.txt ")) {
                        print_getinfo_json();
                        goto www_done;
                    }
                    if ((currentLine.startsWith("GET / ")) ||
                        (currentLine.startsWith("GET /index.html "))) {
                        print_getinfo();
                        goto www_done;
                    }
                    if (currentLine.startsWith("GET /getinfo.html ")) {
                        print_getinfo();
                        goto www_done;
                    }
                    if (currentLine.startsWith("GET /fingerprint ")) {
                        print_fingerprint();
                        goto www_done;
                    }
                    if (currentLine.startsWith("POST /v2c ")) {
                        post_file(POST_FILE_V2C);
                        goto www_done;
                    }
                    if (currentLine.startsWith("POST /rsakey ")) {
                        post_file(POST_FILE_RSA);
                        goto www_done;
                    }
                    if (currentLine.startsWith("POST /aeskey ")) {
                        post_file(POST_FILE_AES);
                        goto www_done;
                    }
                    if ((currentLine.startsWith("GET /dump.txt ")) ||
                            (currentLine.startsWith("GET /dump "))) {
                        dump_v2c_and_keys();
                        goto www_done;
                    }
                    if (currentLine.startsWith("GET /dump.html ")) {
                        dump_v2c_and_keys_html();
                        goto www_done;
                    }
                    if (currentLine.startsWith("GET /set?")) {
                        get_set(currentLine.c_str());
                        goto www_done;
                    }
                    if (currentLine.startsWith("GET /consume?")) {
                        get_consume(currentLine.c_str());
                        goto www_done;
                    }
//MAH
					if (currentLine.startsWith("GET /led1toggle")) { //Green
						ledtoggle(1);
						goto www_done;
					}

					 if (currentLine.startsWith("GET /led2toggle")) { //Blue
						ledtoggle(2);
						goto www_done;
					}
//MAH
                    if (currentLine.startsWith("GET /eraseee")) {
                        erase_ee();
                        goto www_done;
                    }
                    if (currentLine.startsWith("GET /gemalto.png ")) {
                        get_logo();
                        goto www_done;
                    }

                    print404();
                    goto www_done;
                }
                currentLine += c;

            }
        }

        www_done:
        www.stop();

    }

} /* do_www() */

/***********************************************************************************************************/

void www_server_init (void)
{
    server.begin();
}

/***********************************************************************************************************/
