/*
 * Copyright (c) 2007, Swedish Institute of Computer Science.
 * All rights reserved.
 *
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
 * $Id: example-trickle.c,v 1.5 2010/01/15 10:24:37 nifi Exp $
 */

/**
 * \file
 *         Example for using the trickle code in Rime
 * \author
 *         Adam Dunkels <adam@sics.se>
 */

#include "contiki.h"
#include "net/rime/trickle.h"
#include "dev/leds.h"
#include "dtn.h"
#include <stdio.h>
#ifdef CONTIKI_TARGET_ORISENPRIME
#include <button-sensors.h>
#endif

#ifdef CONTIKI_TARGET_ORISENPRIME   
#define TOTAL_MOTES 12
#else
#define TOTAL_MOTES 128
#endif
#define FLASH_LED(l) {leds_on(l); clock_delay_msec(50); leds_off(l); clock_delay_msec(50);}

/*---------------------------------------------------------------------------*/
PROCESS(dtn_process, "DTN Endpoint Process");
AUTOSTART_PROCESSES(&dtn_process);
/*---------------------------------------------------------------------------*/
static void
dtn_recv(struct dtn_conn *c, const rimeaddr_t *from)
{ 
  printf("dtn_recv: epacketid:%d\n", ((struct msg_header *) packetbuf_hdrptr())->epacketid);
#ifdef CONTIKI_TARGET_ORISENPRIME   
  FLASH_LED(LEDS_BLUE);
#endif
}

const static struct dtn_callbacks dtn_cb = { dtn_recv };
static struct dtn_conn dtn_connection;
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(dtn_process, ev, data)
{
  static struct etimer et;
  static uint16_t stats = 0;
  PROCESS_EXITHANDLER(dtn_close(&dtn_connection);)
  PROCESS_BEGIN();
  random_init(*(uint16_t*)(&rimeaddr_node_addr));
  static rimeaddr_t dest_addr, my_addr;
#ifdef CONTIKI_TARGET_ORISENPRIME
  SENSORS_ACTIVATE(button_sensor);
  rimeaddr_copy(&my_addr,&rimeaddr_null);
  my_addr.u8[0] = 11;
  rimeaddr_copy(&rimeaddr_node_addr, &my_addr);
#endif
  dtn_open(&dtn_connection, DTN_SPRAY_CHANNEL, &dtn_cb);
  //set_power(0x02);
  while(1) {
//  PROCESS_WAIT_EVENT_UNTIL(ev   == sensors_event &&
//		     data == &button_sensor);
    etimer_set(&et, CLOCK_SECOND * 6 + random_rand() % (CLOCK_SECOND * 6));
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    rimeaddr_copy(&dest_addr,&rimeaddr_null);
    dest_addr.u8[0] = random_rand() % TOTAL_MOTES;
    if (dtn_is_busy(&dtn_connection)) continue;
    packetbuf_copyfrom("DTN", 4);
    dtn_send(&dtn_connection, &dest_addr);
#ifdef CONTIKI_TARGET_ORISENPRIME   
    FLASH_LED(LEDS_GREEN);
#endif
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
