#ifndef __DTN_H__
#define __DTN_H__
#include "sys/ctimer.h"
#include "net/rime/runicast.h"
#include "net/rime/rimeaddr.h"
#include <stdio.h>

#define DEBUG 0

#define DTN_L_COPIES 8 /*!< Initial L copies a packet Originator would hold*/
#define DTN_QUEUE_MAX 5 /*!< Length of packetqueue items to keep */
#define DTN_MAX_LIFETIME 60 /*!< Total number of time in seconds a packet is expected to spend in the packet queue */
#define DTN_SPRAY_CHANNEL 128 
#define DTN_SPRAY_DELAY 4
#define DTN_RTX 3
#define DTN_HDR_VERSION 1

#define PRINTF(...) printf(__VA_ARGS__)
#if DEBUG
#define DPRINTF(...) printf(__VA_ARGS__)
#else
#define DPRINTF(...)
#endif

#ifdef CONTIKI_TARGET_ORISENPRIME
#define DPRINT2ADDR(addr) DPRINTF("%02x%02x:%02x%02x",(addr)->u8[3], (addr)->u8[2], (addr)->u8[1], (addr)->u8[0])
#define PRINT2ADDR(addr) PRINTF("%02x%02x:%02x%02x",(addr)->u8[3], (addr)->u8[2], (addr)->u8[1], (addr)->u8[0])
#else
#define DPRINT2ADDR(addr) DPRINTF("%02x%02x",(addr)->u8[1], (addr)->u8[0])
#define PRINT2ADDR(addr) PRINTF("%02x%02x",(addr)->u8[1], (addr)->u8[0])
#endif
/**
 * @brief struct for the message header as defined by the DTN protocol. This is to be sent before any payload from the user
 */
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

/**
 * @brief struct for holding the function pointer references for callbacks
 */
struct dtn_callbacks {
	void (* recv)(struct dtn_conn *c, const rimeaddr_t *from, uint16_t packet_id);
};

/**
 * @brief struct to hold the details of the DTN connection. All values here are initialised during dtn_open.
 */
struct dtn_conn {
	struct broadcast_conn spray_c;
	struct unicast_conn request_c;
	struct runicast_conn handoff_c;
	const struct dtn_callbacks *cb;
	struct packetqueue *q;
	uint8_t seqno;
  struct ctimer t;
  struct queuebuf *handoff_qb;
};

/**
 * @brief	Opens a new DTN Connection 
 *
 * @param c	A pointer to a struct dtn_conn
 * @param channel  The lowest channel on which it and the following two channels the connection will operate
 * @param cb	A struct dtn_callbacks with a function pointer for callbacks
 *
 * 		This function opens a new DTN connection using channel, channel + 1 and channel + 2.
 * 		The caller must have allocated memory for a struct dtn_conn before passing a pointer to it.
 */
void dtn_open(struct dtn_conn *c, uint16_t channel,
		const struct dtn_callbacks *cb);

/**
 * @brief 	Closes an existing DTN Connection
 *
 * @param c	A pointer to the struct dtn_conn
 * 		
 * 		c should point to the same struct dtn_conn that was passed into dtn_open
 * 		This function closes all three channels at once so they may be used for other purposes thereafter
 */
void dtn_close(struct dtn_conn *c);

/**
 * @brief 	Attempts to send a packet via the delay tolerant network
 *
 * @param c	A pointer to the struct dtn_conn on which the packet would be sent
 * @param dest	A pointer to the rimeaddr_t of the destination of the packet.
 *
 * @return	Non-zero if the packet could be queued for sending.
 * 		
 * 		The packet must have been formed in the packetbuf before this function
 * 		is called
 *
 */
int dtn_send(struct dtn_conn *c, const rimeaddr_t *dest);

#endif //__DTN_H__
