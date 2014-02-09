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
/*
#define DTN_COMMON_ATTRIBUTES \
				{ PACKETBUF_ADDR_ESENDER, PACKETBUF_ADDRSIZE }, \
				{ PACKETBUF_ADDR_ERECEIVER, PACKETBUF_ADDRSIZE }, \

         { PACKETBUF_ATTR_EPACKET_ID, PACKETBUF_ATTR_BIT * 4 }, \
#define DTN_COMMON_ATTRIBUTES \
				{ PACKETBUF_ADDR_ESENDER, PACKETBUF_ADDRSIZE }, \

#define DTN_SPRAY_ATTRIBUTES DTN_COMMON_ATTRIBUTES BROADCAST_ATTRIBUTES
#define DTN_REQUEST_ATTRIBUTES DTN_COMMON_ATTRIBUTES UNICAST_ATTRIBUTES
#define DTN_HANDOFF_ATTRIBUTES DTN_COMMON_ATTRIBUTES RUNICAST_ATTRIBUTES
*/

#define DTN_QUEUE_MAX 5
#define DTN_MAX_LIFETIME 10
#define DTN_SPRAY_CHANNEL 128 
#define DTN_SPRAY_DELAY 2
#define DTN_RTX 3
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
	void (* recv)(struct dtn_conn *c, const rimeaddr_t *from);
};

struct dtn_conn {
	struct broadcast_conn spray_c;
	struct unicast_conn request_c;
	struct runicast_conn handoff_c;
	const struct dtn_callbacks *cb;
	struct packetqueue *q;
	uint8_t seqno;
  struct ctimer t;
  uint16_t lock;
  struct queuebuf *handoff_qb;
  struct msg_header *hdr;
};

void dtn_open(struct dtn_conn *c, uint16_t channel,
		const struct dtn_callbacks *cb);

void dtn_close(struct dtn_conn *c);

void dtn_send(struct dtn_conn *c, const rimeaddr_t *dest);

int dtn_is_busy(struct dtn_conn *c);
#endif //__DTN_H__
