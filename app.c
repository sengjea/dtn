/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 *
 * $Id: app.c,v 1.5 2010/01/15 10:24:37 nifi Exp $
 */

/**
 * \file
 *         Example for using DTN module
 * \author
 *         Seng Jea, Lee <sengjea@gmail.com>
 */

#include "contiki.h"
#include "net/rime/trickle.h"
#include "dev/leds.h"
#include "dtn.h"
#include <stdio.h>
#ifdef CONTIKI_TARGET_ORISENPRIME
#include <button-sensors.h>
#else
#include "dev/button-sensor.h"
#endif

#define TOTAL_MOTES 32
//#define ORIGIN_ADDR 18
#define DEST_ADDR 1
#define DTN_BUTTON_FIRE
#ifdef CONTIKI_TARGET_ORISENPRIME
#define FLASH_LED(l) {leds_on(l); clock_delay_msec(50); leds_off(l); clock_delay_msec(50);}
#define DTN_LOW_POWER set_power(0x0)
#else
#define FLASH_LED(l) //{leds_on(l); clock_delay(400); leds_off(l); clock_delay(400);}
#endif

/*---------------------------------------------------------------------------*/
PROCESS(dtn_process, "DTN Endpoint Process");
AUTOSTART_PROCESSES(&dtn_process);
/*---------------------------------------------------------------------------*/
static void
dtn_recv(struct dtn_conn *c, const rimeaddr_t *from, uint16_t packet_id)
{ 
  static uint8_t stats = 0;
  stats++;
  PRINTF("dtn_recv: { packet_id:%d stats:%d }\n", packet_id, stats);
  FLASH_LED(LEDS_BLUE);
}
static void
make_random_addr(rimeaddr_t *addr_ptr) {
  rimeaddr_copy(addr_ptr, &rimeaddr_null);
  addr_ptr->u8[0] = (random_rand() % TOTAL_MOTES) + 2;
}
const static struct dtn_callbacks dtn_cb = { dtn_recv };
static struct dtn_conn dtn_connection;
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(dtn_process, ev, data)
{
  static struct etimer et;
  PROCESS_EXITHANDLER(dtn_close(&dtn_connection);)
  PROCESS_BEGIN();
  static rimeaddr_t dest_addr;

#ifdef CONTIKI_TARGET_ORISENPRIME
  SENSORS_ACTIVATE(button_sensor);
  PROCESS_WAIT_EVENT_UNTIL(ev == sensors_event &&
		     data == &button_sensor);
  random_init(clock_time());
#else
  random_init(rimeaddr_node_addr.u8[0]);
#endif

#ifdef ORIGIN_ADDR
  rimeaddr_copy(&rimeaddr_node_addr, &rimeaddr_null);
  rimeaddr_node_addr.u8[0] = ORIGIN_ADDR;
#endif

#ifdef DTN_LOW_POWER
  DTN_LOW_POWER;
#endif

  PRINTF("Init Complete: ");
  PRINT2ADDR(&rimeaddr_node_addr);
  PRINTF("\n");
  dtn_open(&dtn_connection, DTN_SPRAY_CHANNEL, &dtn_cb);
  while(1) {

#ifndef DTN_BUTTON_FIRE
    etimer_set(&et, CLOCK_SECOND * 3 + random_rand() % (CLOCK_SECOND * 5));
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
#else
    PRINTF("<press button to fire>\n");
    PROCESS_WAIT_EVENT_UNTIL(ev   == sensors_event &&
		     data == &button_sensor);
#endif

#ifdef DEST_ADDR
      rimeaddr_copy(&dest_addr, &rimeaddr_null);
      dest_addr.u8[0] = DEST_ADDR;
#else
      make_random_addr(&dest_addr);
#endif
      packetbuf_copyfrom("Seng", 5);
      dtn_send(&dtn_connection, &dest_addr);
      FLASH_LED(LEDS_GREEN);
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
