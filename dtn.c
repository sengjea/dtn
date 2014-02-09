/**
 * \addtogroup rimerunicast
 * @{
 */


/*
 * Copyright (c) 2006, Swedish Institute of Computer Science.
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
 * $Id: runicast.c,v 1.12 2010/03/26 12:29:29 nifi Exp $
 */

/**
 * \file
 *         Reliable unicast
 * \author
 *         Adam Dunkels <adam@sics.se>
 */

#include "contiki.h"
#include "net/rime.h"
#include "dtn.h"
#include <stddef.h>
#include "net/rime/runicast.h"
#include "net/packetqueue.h"
#include <string.h>

static void dtn_rebroadcast(void *vc);
/*
   static const struct packetbuf_attrlist spray_attributes[] =
   { DTN_SPRAY_ATTRIBUTES PACKETBUF_ATTR_LAST };
   static const struct packetbuf_attrlist request_attributes[] =
   { DTN_REQUEST_ATTRIBUTES PACKETBUF_ATTR_LAST };
   static const struct packetbuf_attrlist handoff_attributes[] =
   { DTN_HANDOFF_ATTRIBUTES PACKETBUF_ATTR_LAST };
   */

#ifdef CONTIKI_TARGET_ORISENPRIME   
#define DEBUG 1
#endif
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else
#define PRINTF(...)
#endif
#define PRINTADDR(addr) PRINTF(" %02x%02x:%02x%02x:%02x%02x:%02x%02x ", ((uint8_t *)addr)[0], ((uint8_t *)addr)[1], ((uint8_t *)addr)[2], ((uint8_t *)addr)[3], ((uint8_t *)addr)[4], ((uint8_t *)addr)[5], ((uint8_t *)addr)[6], ((uint8_t *)addr)[7])
//#define PRINT2ADDR(addr) PRINTADDR(addr->u8)
#define PRINT2ADDR(addr) PRINTF("%02x%02x:%02x%02x",(addr)->u8[0], (addr)->u8[1], (addr)->u8[2], (addr)->u8[3])

PACKETQUEUE(dtn_queue,DTN_QUEUE_MAX);
  struct packetqueue_item *
packetqueue_next(struct packetqueue_item *i)
{
  return list_item_next(i);
}
/*---------------------------------------------------------------------------*/
  static void
set_dtn_header(struct dtn_conn *c)
{
  c->hdr = packetbuf_hdrptr();
}
  static void
copy_dtn_header(struct msg_header *msg_ptr)
{
  packetbuf_hdralloc(sizeof(struct msg_header));
  memcpy(packetbuf_hdrptr(),msg_ptr, sizeof(struct msg_header));
}
  static void
move_hdr_from_data(struct dtn_conn *c)
{
  copy_dtn_header(packetbuf_dataptr());
  packetbuf_hdrreduce(sizeof(struct msg_header));
  set_dtn_header(c);
}
  static void
get_dtn_header_qb(struct queuebuf *qb, struct msg_header **msg_ptr)
{
  *msg_ptr = (struct msg_header *) queuebuf_dataptr(qb);
}

  static int
is_for_me(struct dtn_conn *c)
{
  return (rimeaddr_cmp(&(c->hdr->ereceiver),
        &rimeaddr_node_addr));
}
  static int
is_from_me(struct dtn_conn *c)
{
  return (rimeaddr_cmp(&(c->hdr->esender),
        &rimeaddr_node_addr));
}
  static int
is_duplicate(struct dtn_conn *c, struct queuebuf *qb)
{
  struct msg_header *qb_hdr;
  get_dtn_header_qb(qb,&qb_hdr);
  if (qb_hdr->epacketid ==
      c->hdr->epacketid &&
      rimeaddr_cmp(&(qb_hdr->esender),
        &(c->hdr->esender))) {
    return 1;
  }
  return 0;
}
  static struct queuebuf *
find_in_queue(struct dtn_conn *c)
{
  struct queuebuf *qb;
  struct packetqueue_item *p;
  for (p = packetqueue_first(c->q); p != NULL; p = packetqueue_next(p)) {
    qb = packetqueue_queuebuf(p);
    if (is_duplicate(c,qb)) return qb;
  }
  return NULL;
}

  static  int
dtn_lock(struct dtn_conn *c, uint16_t line)
{
  if (c->lock > 0) {
    PRINTF("c->lock:%d line:%d\n", c->lock, line);
    return 0;
  } else {
    c->lock = line;
    return 1;
  }
}
  static  int
dtn_free(struct dtn_conn *c)
{
  c->lock = 0;
}
  int
dtn_is_busy(struct dtn_conn *c)
{
  return c->lock;
}

  static void
print_qb_packet(struct queuebuf *qb)
{
  if (qb == NULL) return;
  struct msg_header *m = (struct msg_header *) queuebuf_dataptr(qb);
  PRINTF("{ s:");
  PRINT2ADDR(queuebuf_addr(qb, PACKETBUF_ADDR_SENDER));
  PRINTF(", r:");
  PRINT2ADDR(queuebuf_addr(qb, PACKETBUF_ADDR_RECEIVER));
  PRINTF(", o:");
  PRINT2ADDR(&m->esender);
  PRINTF(", d:");
  PRINT2ADDR(&m->ereceiver);
  PRINTF(", id:%d, copies:%d } %s\n", m->epacketid,
      m->num_copies,
      (char *) (queuebuf_dataptr(qb) + sizeof(struct msg_header)));
}

  static void
printqueue(struct dtn_conn *c)
{
  struct packetqueue_item *p;
  struct queuebuf *qb;
  PRINTF("dtn_queue:\n");
  for (p = packetqueue_first(c->q);
      p != NULL;
      p = packetqueue_next(p)) {
    qb = packetqueue_queuebuf(p);
    print_qb_packet(qb);
  }
}

  static void
print_packetbuf(char *func)
{
  //if (packetbuf_hdrlen() < sizeof(struct msg_header)) return;
  struct msg_header *msg = (struct msg_header *) packetbuf_hdrptr();
  PRINTF("%s: { s:", func);
  PRINT2ADDR(packetbuf_addr(PACKETBUF_ADDR_SENDER));
  PRINTF(", r:");
  PRINT2ADDR(packetbuf_addr(PACKETBUF_ADDR_RECEIVER));
  PRINTF(", o:");
  PRINT2ADDR(&msg->esender);
  PRINTF(", d:");
  PRINT2ADDR(&msg->ereceiver);
  PRINTF(", id:%d, copies:%d } %s\n",msg->epacketid,
      msg->num_copies, packetbuf_dataptr()); 
}

  static void
wind_timer(struct dtn_conn *c)
{
  struct packetqueue_item *p = packetqueue_first(c->q);
  if (p != NULL && ctimer_expired(&c->t)) {
    PRINTF("wind_timer\n");
    ctimer_set(&c->t, DTN_SPRAY_DELAY * CLOCK_SECOND, dtn_rebroadcast, c);
  }
  printqueue(c);  
}

  void
sent_handoff(struct runicast_conn *ru_c, const rimeaddr_t *to , uint8_t rtx)
{
  struct dtn_conn *c = (struct dtn_conn *) ((char *) ru_c -
      offsetof(struct dtn_conn, handoff_c));
  struct msg_header *msg_ptr;
  if (c->handoff_qb != NULL) {
    PRINTF("sent_handoff\n");
    print_qb_packet(c->handoff_qb);
    get_dtn_header_qb(c->handoff_qb,&msg_ptr);
    msg_ptr->num_copies = msg_ptr->num_copies/2;
  }
  c->handoff_qb = NULL;
  dtn_free(c);

}
  void
failed_handoff(struct runicast_conn *ru_c, const rimeaddr_t *to, uint8_t rtx)
{
  struct dtn_conn *c = (struct dtn_conn *) ((char *) ru_c -
      offsetof(struct dtn_conn, handoff_c));
  PRINTF("failed_handoff\n");
  c->handoff_qb = NULL;
  dtn_free(c);
}

  void
recv_handoff(struct runicast_conn *ru_c, const rimeaddr_t *from, uint8_t seqno)
{
  struct dtn_conn *c = (struct dtn_conn *) ((char *) ru_c -
      offsetof(struct dtn_conn, handoff_c));
  struct queuebuf * qb;
  struct msg_header *qb_hdr;
  if (!dtn_lock(c,__LINE__)) return;
  PRINTF("recv_handoff\n");
  move_hdr_from_data(c);
  qb = find_in_queue(c);
  if (qb != NULL) {
    get_dtn_header_qb(qb,&qb_hdr);
    qb_hdr->num_copies = c->hdr->num_copies;
  }
  dtn_free(c);
}

  void
recv_request(struct unicast_conn *u_c, const rimeaddr_t *from)
{
  struct dtn_conn *c = (struct dtn_conn *) ((char *) u_c -
      offsetof(struct dtn_conn, request_c));

  struct queuebuf * qb;
  struct msg_header *msg_ptr;
  PRINTF("recv_request ");
  if (!dtn_lock(c,__LINE__)) return;
  move_hdr_from_data(c);
  qb = find_in_queue(c);
  if (qb != NULL) {
    print_packetbuf("send_handoff");
    get_dtn_header_qb(qb,&msg_ptr);
    c->hdr->num_copies = msg_ptr->num_copies/2;
    c->handoff_qb = qb;
    runicast_send(&c->handoff_c, from, DTN_RTX);
  } else {
    dtn_free(c); 
  }
  PRINTF("\n");
}
  static void
_send_request(struct dtn_conn *c)
{
  const rimeaddr_t *to;
  packetbuf_set_datalen(0);
  print_packetbuf("send_request");
  to = packetbuf_addr(PACKETBUF_ADDR_SENDER);
  unicast_send(&c->request_c, to);
}

  void
recv_spray(struct broadcast_conn *b_c, const rimeaddr_t *from)
{
  struct dtn_conn *c = (struct dtn_conn *) ((char *) b_c -
      offsetof(struct dtn_conn, spray_c));
  PRINTF("recv_spray ");
  if (!dtn_lock(c,__LINE__)) return;
  move_hdr_from_data(c);
  print_packetbuf("recv_broadcast");
  if (is_for_me(c)) {
    PRINTF("is_for_me ");
    c->cb->recv(c, from);
  } else if (!is_from_me(c)) {
    if (find_in_queue(c) == NULL) {
      PRINTF("!find_in_queue ");
      c->hdr->num_copies = 0;
      if (packetqueue_enqueue_packetbuf(c->q,
            DTN_MAX_LIFETIME * CLOCK_SECOND, c)) {
        PRINTF("spray queued ");
        _send_request(c);
      }
    }
    PRINTF("\n");
  }
  wind_timer(c);
  dtn_free(c); 
}
/*---------------------------------------------------------------------------*/
static const struct broadcast_callbacks spray_cb = { recv_spray };
static const struct unicast_callbacks request_cb = { recv_request };
static const struct runicast_callbacks handoff_cb = { recv_handoff, sent_handoff, failed_handoff };
/*---------------------------------------------------------------------------*/
  void
dtn_open(struct dtn_conn *c, uint16_t channel,
    const struct dtn_callbacks *cb)
{
  PRINTF("DTN Open with Broadcast:%d, Unicast:%d, Runicast:%d\n",channel, channel + 1, channel + 2); 
  broadcast_open(&c->spray_c, channel, &spray_cb);
  unicast_open(&c->request_c, channel+1, &request_cb);
  runicast_open(&c->handoff_c, channel+2, &handoff_cb);
  c->cb = cb;
  packetqueue_init(&dtn_queue);
  c->q = &dtn_queue;
}
/*---------------------------------------------------------------------------*/
  void
dtn_close(struct dtn_conn *c)
{
  broadcast_close(&c->spray_c);
  unicast_close(&c->request_c);
  runicast_close(&c->handoff_c);
}
/*---------------------------------------------------------------------------*/
  void
dtn_send(struct dtn_conn *c, const rimeaddr_t *dest)
{
  if (!dtn_lock(c,__LINE__)) return;
  struct msg_header msg = { .num_copies = DTN_L_COPIES };
  c->seqno = c->seqno + 1;
  msg.epacketid = c->seqno;
  rimeaddr_copy(&msg.ereceiver,dest);
  rimeaddr_copy(&msg.esender,&rimeaddr_node_addr);
  //packetbuf_set_attr(PACKETBUF_ATTR_EPACKET_ID, c->seqno);
  //packetbuf_set_addr(PACKETBUF_ADDR_ESENDER, &rimeaddr_node_addr);
  //packetbuf_set_addr(PACKETBUF_ADDR_ERECEIVER, dest);
  copy_dtn_header(&msg);
  if (packetqueue_enqueue_packetbuf(c->q, DTN_MAX_LIFETIME * CLOCK_SECOND, c)) {
    print_packetbuf("dtn_send");
  } else {
    c->seqno = c->seqno + 1;
  }
  wind_timer(c);
  dtn_free(c);
}

  static void
dtn_rebroadcast(void *vc)
{
  struct dtn_conn *c = (struct dtn_conn *) vc;
  struct packetqueue_item *p = packetqueue_first(c->q);
  struct queuebuf *qb;
  if (!dtn_lock(c,__LINE__)) return;
  if (p != NULL) {
    qb = packetqueue_queuebuf(p);
    queuebuf_to_packetbuf(qb);
    print_packetbuf("dtn_rebroadcast");
    set_dtn_header(c);
    if (is_from_me(c)) {
      if (c->hdr->num_copies > 2) {
        c->hdr->num_copies = c->hdr->num_copies - 2;
        packetqueue_enqueue_packetbuf(c->q, DTN_MAX_LIFETIME * CLOCK_SECOND, c);
        c->hdr->num_copies = c->hdr->num_copies + 2;
      }
      broadcast_send(&c->spray_c);
    } else {
      if (c->hdr->num_copies == 0) {
        c->hdr->num_copies = 1;
        packetqueue_enqueue_packetbuf(c->q, (DTN_MAX_LIFETIME / 2) * CLOCK_SECOND, c);
        _send_request(c); 
      }
    }
    packetqueue_dequeue(c->q);
  }
  wind_timer(c);
  dtn_free(c);
}
/*---------------------------------------------------------------------------*/
/** @} */
