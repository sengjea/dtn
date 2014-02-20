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
}

/*
 * Packet comparison functions
 * ---------------------------------------------------------------------------*/
  static int
packet_is_for_me(struct msg_header *a)
{
  return (rimeaddr_cmp(&(a->ereceiver),
        &rimeaddr_node_addr));
}
  static int
packet_is_from_me(struct msg_header *a)
{
  return (rimeaddr_cmp(&(a->esender),
        &rimeaddr_node_addr));
}

/*
 * Packet Queue functions
 * ---------------------------------------------------------------------------*/

//returns 1 if same else 0
  static int
msg_header_cmp(struct msg_header *a, struct msg_header *b)
{
  return (a->epacketid == b->epacketid &&
      rimeaddr_cmp(&(a->esender), &(b->esender)));
}
  static int
packet_is_from_destination(struct msg_header *a)
{
  return (rimeaddr_cmp(&(a->ereceiver),
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
  ctimer_restart(&i->lifetimer);
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
find_item_in_queue(struct packetqueue *q, struct msg_header *a)
{
  struct packetqueue_item *p;
  struct queuebuf *qb;
  for (p = packetqueue_first(q); p != NULL; p = packetqueue_next(p)) {
    qb = packetqueue_queuebuf(p);
    if (qb == NULL) continue;
    if (msg_header_cmp(a,(struct msg_header *) queuebuf_dataptr(qb))) return p;
  }
  return NULL;
}
  static struct packetqueue_item *
find_least_critical(struct packetqueue *q)
{
  uint16_t i,v = DTN_L_COPIES/2; 
  struct packetqueue_item *p, *l = NULL;
  struct msg_header *qb_hdr;
  struct queuebuf *qb;
  i = 1;
  for (p = packetqueue_first(q); p != NULL; p = packetqueue_next(p)) {
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
dtn_enqueue_packetbuf(struct packetqueue *q)
{
  struct packetqueue_item *i;
  if (packetqueue_len(q) >= DTN_QUEUE_MAX) {
    i = find_least_critical(q);
    if (i == NULL) {
      return 0;
    }
    packetqueue_remove_item(i); 
  }
  return packetqueue_enqueue_packetbuf(q, DTN_MAX_LIFETIME * CLOCK_SECOND, NULL);
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
print_packetqueue(struct packetqueue *q)
{
  struct packetqueue_item *p;
  struct queuebuf *qb;
  PRINTF("dtn_queue:");
  p = packetqueue_first(q);
  if (p == NULL)
    PRINTF(" (empty)");
  PRINTF("\n");
  for (;p != NULL; p = packetqueue_next(p)) {
    qb = packetqueue_queuebuf(p);
    print_queuebuf(qb);
  }
}
  static int
is_a_dtn_packet(struct msg_header *a)
{
  return (a != NULL &&
      a->protocol.version == DTN_HDR_VERSION &&
      a->protocol.magic[0] == 'S' &&
      a->protocol.magic[1] == 'W');
}
  static void
print_packetbuf(struct msg_header *a, char *func)
{
  PRINTF("%s: { s:", func);
  PRINT2ADDR(packetbuf_addr(PACKETBUF_ADDR_SENDER));
  PRINTF(", r:");
  PRINT2ADDR(packetbuf_addr(PACKETBUF_ADDR_RECEIVER));
  if (is_a_dtn_packet(a)) {
    PRINTF(", o:");
    PRINT2ADDR(&a->esender);
    PRINTF(", d:");
    PRINT2ADDR(&a->ereceiver);
    PRINTF(", id:%d, copies:%d } ",a->epacketid,
        a->num_copies); 
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
  print_packetqueue(c->q);  
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
  struct msg_header *qb_hdr, *pb_hdr;
  pb_hdr =(struct msg_header *) packetbuf_dataptr(); 
  print_packetbuf(pb_hdr,"recv_handoff");
  if (!is_a_dtn_packet(pb_hdr)) goto fail;
  p = find_item_in_queue(c->q, pb_hdr);
  if (p == NULL) goto fail;
  qb_hdr = queuebuf_dataptr(packetqueue_queuebuf(p));
  qb_hdr->num_copies += pb_hdr->num_copies;
  if (qb_hdr->num_copies > DTN_L_COPIES) {
    qb_hdr->num_copies = DTN_L_COPIES;
  }
  packetqueue_refresh(p);
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
  struct msg_header *qb_hdr, *pb_hdr;
  pb_hdr = (struct msg_header *) packetbuf_dataptr();
  print_packetbuf(pb_hdr,"recv_request");
  if (!is_a_dtn_packet(pb_hdr)) goto done;
  i = find_item_in_queue(c->q, pb_hdr);
  if (i == NULL) goto done;
  PRINTF("in_queue ");
  if (packet_is_from_destination(pb_hdr)) {
    PRINTF("reached ");
    //TODO: Make E-Receiver NULL.

  } else {
    struct queuebuf *qb;
    if (c->handoff_qb != NULL) goto done;
    qb = packetqueue_queuebuf(i);
    if (qb == NULL) goto done;
    qb_hdr = queuebuf_dataptr(qb);
    if (qb_hdr->num_copies == 1) goto done;
    c->handoff_qb = packetqueue_queuebuf(i);
    packetbuf_copyfrom(qb_hdr, sizeof(struct msg_header));
    pb_hdr = (struct msg_header *) packetbuf_dataptr();
    pb_hdr->num_copies = pb_hdr->num_copies/2;
    print_packetbuf(pb_hdr,"send_handoff");
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
  struct msg_header spray_hdr, *pb_hdr;
  pb_hdr = packetbuf_dataptr();
  if (!is_a_dtn_packet(pb_hdr)) return;
  memcpy(&spray_hdr, pb_hdr, sizeof(struct msg_header));
  if (packet_is_for_me(pb_hdr)) {
    packetbuf_hdrreduce(sizeof(struct msg_header));
    c->cb->recv(c, &(spray_hdr.esender), spray_hdr.epacketid);
  } else if (packet_is_from_me(pb_hdr) ||
                pb_hdr->num_copies == 1 || find_item_in_queue(c->q, pb_hdr) != NULL) { 
    print_packetbuf(pb_hdr,"spray_ignored");
    return;
  } else {
    pb_hdr->num_copies = 0;
    if (!dtn_enqueue_packetbuf(c->q)) return;
    PRINTF("queued ");
  }

  packetbuf_copyfrom(&spray_hdr, sizeof(struct msg_header));
  unicast_send(&c->request_c, from);
  print_packetbuf(packetbuf_dataptr(),"send_request");
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
  struct packetqueue_item *p;
  msg.epacketid = ++seqno;
  rimeaddr_copy(&msg.ereceiver,dest);
  rimeaddr_copy(&msg.esender,&rimeaddr_node_addr);
  prepend_header(c,&msg);
  if (dtn_enqueue_packetbuf(c->q)) {
    p = find_item_in_queue(c->q, (struct msg_header *) packetbuf_hdrptr());
    queuebuf_to_packetbuf(packetqueue_queuebuf(p));
    print_packetbuf((struct msg_header *) packetbuf_dataptr(),"dtn_send");
    broadcast_send(&c->spray_c);
    wind_timer(c);
  } else {
    seqno--;
  }
}
/*---------------------------------------------------------------------------*/

  static void
dtn_service_queue(void *vc)
{
  struct dtn_conn *c = (struct dtn_conn *) vc;
  struct queuebuf *qb;
  struct packetqueue_item *p;
  struct msg_header *qb_hdr;
  rimeaddr_t to;
  
  for (p = packetqueue_first(c->q); p != NULL; p = packetqueue_next(p)) {
      qb = packetqueue_queuebuf(p);
      if (qb == NULL) continue;
      queuebuf_to_packetbuf(qb);
      qb_hdr = (struct msg_header *) queuebuf_dataptr(qb);
      if (qb_hdr->num_copies == 0) {
        //If num_copies == 0, handoff was never received. resend_request;
        qb_hdr->num_copies = 1;
        //packetqueue_enqueue_packetbuf(c->q, DTN_MAX_LIFETIME * CLOCK_SECOND, c);
        packetbuf_set_datalen(sizeof(struct msg_header));
        rimeaddr_copy(&to,packetbuf_addr(PACKETBUF_ADDR_SENDER));
        unicast_send(&c->request_c, &to);
        print_packetbuf(packetbuf_dataptr(),"resend_request");
      } else {
        /*
        if (c->hdr->num_copies > 1) {
            packetqueue_refresh(p);
            //packetqueue_dequeue(c->q);
        }
        */
        print_packetbuf(packetbuf_dataptr(),"dtn_broadcast");
        broadcast_send(&c->spray_c);
      }
  }
  wind_timer(c);
}
/*---------------------------------------------------------------------------*/
/** @} */
