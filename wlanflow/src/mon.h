#ifndef MON_H
#define MON_H

#include <OFConnectionManager/ofconnectionmanager_config.h>
#include <OFConnectionManager/ofconnectionmanager.h>

#include <inttypes.h>

/* Callback type for received wireless packets */
typedef void (rtap_cb)(indigo_cxn_id_t cxn_id, size_t n_bytes,
    unsigned char *rtap_hdr_and_pkt, unsigned char *pkt, uint32_t port);

int mon_init(char **interfaces, size_t n, pthread_mutex_t *mutex,
	         indigo_cxn_id_t cxn_id);
void mon_stop(void);

#endif /* MON_H */

