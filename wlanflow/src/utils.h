#ifndef __UTILS_H_
#define __UTILS_H_

#include <stdlib.h>
#include <string.h>
#include <netinet/ether.h>
#include <linux/nl80211.h>

#include "wlanflow.h"

#define INFO_BUF_INITSIZE 8

/* Dynamic buffer for fixed-type data
 */
struct info_buf {
	const size_t el_size;
	size_t n_el;
	size_t size;
	unsigned char *pos;
	unsigned char *buf;
};

#define INFO_BUF_INIT(_type)	\
{								\
	.el_size = sizeof(_type),	\
	.n_el = 0,					\
	.size = 0,					\
	.pos = NULL,				\
	.buf = NULL,				\
}

#define INFO_BUFSIZE_BYTES(_b) ((_b)->size * (_b)->el_size)

inline void
info_buf_reset(struct info_buf *buf)
{
	buf->n_el = 0;
	buf->pos = NULL;
	buf->buf = NULL;
}

int info_buf_append(struct info_buf *buf, void *data);

void info_buf_free(struct info_buf *buf);

void _DEBUG_print_wphy(struct wphy_info *phy);
void _DEBUG_print_station_info(union station_info *sta, bool encrypted);
void _DEBUG_print_sdwn_nic_entity(void *nic);
void _DEBUG_print_sdwn_accesspoint_entity(void *ap);
void _DEBUG_print_sdwn_related_switch_entity(void *sw);
void _DEBUG_print_sdwn_entities(void *list);

size_t hexparse(const char *hexstring, uint8_t *buf);

int ieee80211_channel_to_frequency(uint8_t chan, enum nl80211_band band);

int ieee80211_frequency_to_channel(int freq);

#endif