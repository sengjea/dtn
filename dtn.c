/**
 * \addtogroup dtn
 * @{
 */


/*
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
 * $Id: dtn.c,v 1.12 2010/03/26 12:29:29 nifi Exp $
 */

/**
 * \file
 *         Delay Tolerant Network
 * \author
 *         Seng Jea <sengjea@gmail.com>
 */

#include "contiki.h"
#include "net/rime.h"
#include "dtn.h"
#include <stddef.h>
#include "net/rime/runicast.h"
#include "net/packetqueue.h"
#include <string.h>

static void dtn_service_queue(void *vc);
/*
   static const struct packetbuf_attrlist spray_attributes[] =
   { DTN_SPRAY_ATTRIBUTES PACKETBUF_ATTR_LAST };
   static const struct packetbuf_attrlist request_attributes[] =
   { DTN_REQUEST_ATTRIBUTES PACKETBUF_ATTR_LAST };
   static const struct packetbuf_attrlist handoff_attributes[] =
   { DTN_HANDOFF_ATTRIBUTES PACKETBUF_ATTR_LAST };
   */


PACKETQUEUE(dtn_queue,DTN_QUEUE_MAX);
/*
 * Header helper functions
 * ---------------------------------------------------------------------------*/
  static void
prepend_header(struct dtn_conn *c, struct msg_header *msg_ptr)
{
  packetbuf_hdralloc(sizeof(struct msg_header));
  memcpy(packetbuf_hdrptr(),msg_ptr, sizeof(struct msg_header));
  c->hdr = packetbuf_hdrptr();
}

/*
 * Packet comparison functions
 * ---------------------------------------------------------------------------*/
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

/*
 * Packet Queue functions
 * ---------------------------------------------------------------------------*/

  
  static int
is_duplicate(struct dtn_conn *c, struct packetqueue_item *p)
{
  struct msg_header *qb_hdr;
  struct queuebuf *qb = packetqueue_queuebuf(p);
  if (qb == NULL) return 0;
  qb_hdr = queuebuf_dataptr(qb);
  return (qb_hdr->epacketid == c->hdr->epacketid &&
      rimeaddr_cmp(&(qb_hdr->esender), &(c->hdr->esender)));
}
  static int
is_from_destination(struct dtn_conn *c)
{
  return (rimeaddr_cmp(&(c->hdr->ereceiver),
        packetbuf_addr(PACKETBUF_ADDR_SENDER)));
}
  
  struct packetqueue_item *
packetqueue_next(struct packetqueue_item *i)
{
  return list_item_next(i);
}
  void
packetqueue_refresh(struct packetqueue_item *i)
{
  ctimer_reset(&i->lifetimer);
}
  
  void
packetqueue_remove_item(struct packetqueue_item *i)
{
  struct packetqueue *q = i->queue;
  list_remove(*q->list, i);
  queuebuf_free(i->buf);
  ctimer_stop(&i->lifetimer);
  memb_free(q->memb, i);
}
  static struct packetqueue_item *
find_item_in_queue(struct dtn_conn *c)
{
  struct packetqueue_item *p;
  for (p = packetqueue_first(c->q); p != NULL; p = packetqueue_next(p)) {
    if (is_duplicate(c,p)) return p;
  }
  return NULL;

}
  static struct packetqueue_item *
find_least_critical(struct dtn_conn *c)
{
  uint16_t i,v = DTN_L_COPIES; 
  struct packetqueue_item *p, *l = NULL;
  struct msg_header *qb_hdr;
  struct queuebuf *qb;
  i = 1;
  for (p = packetqueue_first(c->q); p != NULL; p = packetqueue_next(p)) {
    qb = packetqueue_queuebuf(p);
    if (qb == NULL) continue;
    qb_hdr = queuebuf_dataptr(qb);
    if (qb_hdr->num_copies * i < v) {
      v = qb_hdr->num_copies * i;
      l = p;
    }
    i++;
  }
  return l;
}
  
  static int
dtn_enqueue_packetbuf(struct dtn_conn *c)
{
  struct packetqueue_item *i = find_least_critical(c);
  if (packetqueue_len(c->q) >= DTN_QUEUE_MAX && i != NULL) {
    packetqueue_remove_item(i); 
  }
  return packetqueue_enqueue_packetbuf(c->q, DTN_MAX_LIFETIME * CLOCK_SECOND, c);
}

/*
 * Packet Printing Functions.
 * ---------------------------------------------------------------------------*/

  static void
print_raw_packetbuf(void)
{
  uint16_t i;
  PRINTF("\n");
  for(i = 0; i < packetbuf_hdrlen(); i++) {
    PRINTF("%02x ", *(char *)(packetbuf_hdrptr() + i));
  }
  PRINTF("| ");
  for(i = 0; i < packetbuf_datalen(); i++) {
    PRINTF("%02x ", *(char *)(packetbuf_dataptr() + i));
  }
  PRINTF("[%d]\n", (int16_t) (packetbuf_dataptr() - packetbuf_hdrptr()));
}
  static void
print_queuebuf(struct queuebuf *qb)
{
  struct msg_header *qb_hdr;
  if (qb == NULL) return;
  qb_hdr = queuebuf_dataptr(qb);
  PRINTF("{ s:");
  PRINT2ADDR(queuebuf_addr(qb, PACKETBUF_ADDR_SENDER));
  PRINTF(", r:");
  PRINT2ADDR(queuebuf_addr(qb, PACKETBUF_ADDR_RECEIVER));
  PRINTF(", o:");
  PRINT2ADDR(&qb_hdr->esender);
  PRINTF(", d:");
  PRINT2ADDR(&qb_hdr->ereceiver);
  PRINTF(", id:%d, copies:%d }\n", qb_hdr->epacketid,
      qb_hdr->num_copies);
}

  static void
print_packetqueue(struct dtn_conn *c)
{
  struct packetqueue_item *p;
  struct queuebuf *qb;
  PRINTF("dtn_queue:");
  p = packetqueue_first(c->q);
  if (p == NULL)
    PRINTF(" (empty)");
  PRINTF("\n");
  for (;p != NULL; p = packetqueue_next(p)) {
    qb = packetqueue_queuebuf(p);
    print_queuebuf(qb);
  }
}
  static int
is_a_dtn_packet(struct dtn_conn *c)
{
  return (c->hdr != NULL &&
      c->hdr->protocol.version == DTN_HDR_VERSION &&
      c->hdr->protocol.magic[0] == 'S' &&
      c->hdr->protocol.magic[1] == 'W');
}
  static void
print_packetbuf(struct dtn_conn *c, char *func)
{
  PRINTF("%s: { s:", func);
  PRINT2ADDR(packetbuf_addr(PACKETBUF_ADDR_SENDER));
  PRINTF(", r:");
  PRINT2ADDR(packetbuf_addr(PACKETBUF_ADDR_RECEIVER));
  if (is_a_dtn_packet(c)) {
    PRINTF(", o:");
    PRINT2ADDR(&c->hdr->esender);
    PRINTF(", d:");
    PRINT2ADDR(&c->hdr->ereceiver);
    PRINTF(", id:%d, copies:%d } ",c->hdr->epacketid,
        c->hdr->num_copies); 
  } else {
    PRINTF(" ?? } ");
  }
  print_raw_packetbuf();
}
/*---------------------------------------------------------------------------*/

  static void
wind_timer(struct dtn_conn *c)
{
  struct packetqueue_item *p = packetqueue_first(c->q);
  if (p != NULL && ctimer_expired(&c->t)) {
    PRINTF("wind_timer\n");
    ctimer_set(&c->t, DTN_SPRAY_DELAY * CLOCK_SECOND, dtn_service_queue, c);
  }
  print_packetqueue(c);  
}

/*---------------------------------------------------------------------------*/
  void
sent_handoff(struct runicast_conn *ru_c, const rimeaddr_t *to , uint8_t rtx)
{
  struct dtn_conn *c = (struct dtn_conn *) ((char *) ru_c -
      offsetof(struct dtn_conn, handoff_c));
  struct msg_header *qb_hdr;
  if (c->handoff_qb != NULL) {
    //TODO: What if queuebuf dies before this?
    PRINTF("sent_handoff\n");
    qb_hdr = queuebuf_dataptr(c->handoff_qb);
    if (qb_hdr->num_copies > 1) {
      qb_hdr->num_copies -= qb_hdr->num_copies/2;
    }
    print_queuebuf(c->handoff_qb);
  }
  c->handoff_qb = NULL;
}
  void
failed_handoff(struct runicast_conn *ru_c, const rimeaddr_t *to, uint8_t rtx)
{
  struct dtn_conn *c = (struct dtn_conn *) ((char *) ru_c -
      offsetof(struct dtn_conn, handoff_c));
  PRINTF("failed_handoff\n");
  c->handoff_qb = NULL;
}


  void
recv_handoff(struct runicast_conn *ru_c, const rimeaddr_t *from, uint8_t seqno)
{
  struct dtn_conn *c = (struct dtn_conn *) ((char *) ru_c -
      offsetof(struct dtn_conn, handoff_c));
  struct packetqueue_item *p;
  struct msg_header *qb_hdr;
  c->hdr = packetbuf_dataptr();
  print_packetbuf(c,"recv_handoff");
  if (!is_a_dtn_packet(c)) goto fail;
  p = find_item_in_queue(c);
  if (p == NULL) goto fail;
  qb_hdr = queuebuf_dataptr(packetqueue_queuebuf(p));
  qb_hdr->num_copies += c->hdr->num_copies;
  if (qb_hdr->num_copies > DTN_L_COPIES) {
    qb_hdr->num_copies = DTN_L_COPIES;
  }
fail:
  return;
}
/*---------------------------------------------------------------------------*/

  void
recv_request(struct unicast_conn *u_c, const rimeaddr_t *from)
{
  struct dtn_conn *c = (struct dtn_conn *) ((char *) u_c -
      offsetof(struct dtn_conn, request_c));

  struct packetqueue_item *i;
  struct msg_header *qb_hdr;
  c->hdr = packetbuf_dataptr();
  print_packetbuf(c,"recv_request");
  if (!is_a_dtn_packet(c)) goto done;
  i = find_item_in_queue(c);
  if (i == NULL) goto done;
  PRINTF("in_queue ");
  if (is_from_destination(c)) {
    PRINTF("reached ");
    packetqueue_remove_item(i);
  } else {
    if (c->handoff_qb != NULL) goto done;
    qb_hdr = queuebuf_dataptr(packetqueue_queuebuf(i));
    if (qb_hdr->num_copies < 2) goto done;
    c->handoff_qb = packetqueue_queuebuf(i);
    packetbuf_copyfrom(qb_hdr, sizeof(struct msg_header));
    c->hdr = packetbuf_dataptr();
    c->hdr->num_copies = qb_hdr->num_copies/2;
    print_packetbuf(c,"send_handoff");
    runicast_send(&c->handoff_c, from, DTN_RTX);
    return;
  }
done:
  PRINTF("\n");
}

/*---------------------------------------------------------------------------*/

  void
recv_spray(struct broadcast_conn *b_c, const rimeaddr_t *from)
{
  struct dtn_conn *c = (struct dtn_conn *) ((char *) b_c -
      offsetof(struct dtn_conn, spray_c));
  struct msg_header spray_hdr;
  c->hdr = packetbuf_dataptr();
  if (!is_a_dtn_packet(c)) return;
  memcpy(&spray_hdr, c->hdr, sizeof(struct msg_header));
  print_packetbuf(c,"recv_spray");
  if (is_from_me(c)) return;
  if (is_for_me(c)) {
    packetbuf_hdrreduce(sizeof(struct msg_header));
    c->cb->recv(c, &(spray_hdr.esender), spray_hdr.epacketid);
  } else if (spray_hdr.num_copies > 1 && find_item_in_queue(c) == NULL) {
    c->hdr->num_copies = 0;
    if (!dtn_enqueue_packetbuf(c)) {
      print_packetqueue(c);
      return;
    }
  }
  PRINTF("queued ");
  //FIXME: Numcopies must not be predetermined!!
  //Setting num_copies to 0 because no handoff received yet.
  packetbuf_copyfrom(&spray_hdr, sizeof(struct msg_header));
  c->hdr = packetbuf_dataptr();
  print_packetbuf(c,"send_request");
  unicast_send(&c->request_c, from);
  wind_timer(c);
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
  c->hdr = packetbuf_hdrptr();
  c->handoff_qb = NULL;
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
  static uint16_t seqno = 0;
  struct msg_header msg = { .protocol = { .version = DTN_HDR_VERSION,
                                          .magic = "SW" },
                            .num_copies = DTN_L_COPIES };
  msg.epacketid = ++seqno;
  rimeaddr_copy(&msg.ereceiver,dest);
  rimeaddr_copy(&msg.esender,&rimeaddr_node_addr);
  prepend_header(c,&msg);
  if (dtn_enqueue_packetbuf(c)) {
    print_packetbuf(c,"dtn_send");
    broadcast_send(&c->spray_c);
    wind_timer(c);
  } else {
    print_packetqueue(c);
  }
}
/*---------------------------------------------------------------------------*/

  static void
dtn_service_queue(void *vc)
{
  struct dtn_conn *c = (struct dtn_conn *) vc;
  struct queuebuf *qb;
  struct packetqueue_item *p;
  for (p = packetqueue_first(c->q); p != NULL; p = packetqueue_next(p)) {
      qb = packetqueue_queuebuf(p);
      queuebuf_to_packetbuf(qb);
      c->hdr = packetbuf_dataptr();
      if (c->hdr->num_copies == 0) {
        //If num_copies == 0, handoff was never received. resend_request;
        c->hdr->num_copies = 1;
        packetqueue_enqueue_packetbuf(c->q, DTN_MAX_LIFETIME * CLOCK_SECOND, c);
        print_packetbuf(c,"resend_request");
        rimeaddr_t to;
        packetbuf_set_datalen(sizeof(struct msg_header));
        rimeaddr_copy(&to,packetbuf_addr(PACKETBUF_ADDR_SENDER));
        packetqueue_refresh(p);
        unicast_send(&c->request_c, &to);
      } else {
        /*
        if (c->hdr->num_copies > 1) {
            packetqueue_refresh(p);
            //packetqueue_dequeue(c->q);
        }
        */
        print_packetbuf(c,"dtn_broadcast");
        broadcast_send(&c->spray_c);
      }
  }
  wind_timer(c);
}
/*---------------------------------------------------------------------------*/
/** @} */
