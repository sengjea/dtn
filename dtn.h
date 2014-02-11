#ifndef __DTN_H__
#define __DTN_H__
#include "sys/ctimer.h"
#include "net/rime/runicast.h"
#include "net/rime/rimeaddr.h"

#ifndef DTN_CONF_DEFAULT_L_COPIES
#define DTN_L_COPIES 8
#else
#define DTN_L_COPIES DTN_CONF_DEFAULT_L_COPIES
#endif

#define DTN_QUEUE_MAX 5
#define DTN_MAX_LIFETIME 10
#define DTN_SPRAY_CHANNEL 128 
#define DTN_SPRAY_DELAY 2
#define DTN_RTX 3
#define DTN_HDR_VERSION 1
#define DEBUG 1
#if DEBUG
#include <stdio.h>
#define PRINTF(...) printf(__VA_ARGS__)
#else
#define PRINTF(...)
#endif
#ifdef CONTIKI_TARGET_ORISENPRIME
#define PRINT2ADDR(addr) PRINTF("%02x%02x:%02x%02x",(addr)->u8[3], (addr)->u8[2], (addr)->u8[1], (addr)->u8[0])
#else
#define PRINT2ADDR(addr) PRINTF("%02x%02x",(addr)->u8[1], (addr)->u8[0])
#endif
struct proto_header {
  uint8_t version;
  uint8_t magic[2];
};
struct msg_header {
	struct proto_header protocol;
  uint16_t num_copies;
  rimeaddr_t esender;
  rimeaddr_t ereceiver;
  uint16_t epacketid;
};

struct dtn_conn;

struct dtn_callbacks {
	void (* recv)(struct dtn_conn *c, const rimeaddr_t *from, uint16_t packet_id);
};

struct dtn_conn {
	struct broadcast_conn spray_c;
	struct unicast_conn request_c;
	struct runicast_conn handoff_c;
	const struct dtn_callbacks *cb;
	struct packetqueue *q;
	uint8_t seqno;
  struct ctimer t;
  struct queuebuf *handoff_qb;
  struct msg_header *hdr;
};

void dtn_open(struct dtn_conn *c, uint16_t channel,
		const struct dtn_callbacks *cb);

void dtn_close(struct dtn_conn *c);

void dtn_send(struct dtn_conn *c, const rimeaddr_t *dest);

int dtn_is_busy(struct dtn_conn *c);
#endif //__DTN_H__
