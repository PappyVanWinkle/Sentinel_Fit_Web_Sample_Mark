/****************************************************************************\
**
** fit_led.c
**
** LED functions - TM4C1294XL version
**
** Copyright (C) 2016, SafeNet, Inc. All rights reserved.
**
\****************************************************************************/

#include <energia.h>

#define LED_PIN PN_1

void fit_led_on(void)
{
    pinMode(LED_PIN, OUTPUT);
    digitalWrite(LED_PIN, HIGH);
}

void fit_led_off(void)
{
    pinMode(LED_PIN, OUTPUT);
    digitalWrite(LED_PIN, LOW);
}

void fit_led_init(void)
{
	fit_led_off();
}

void fit_led_deinit(void)
{
    fit_led_off();
}
