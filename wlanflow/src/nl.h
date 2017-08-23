#ifndef NL_H
#define NL_H

#include <netinet/ether.h>

#include "wlanflow.h"

int nl_get_mac_address(struct ether_addr* mac, unsigned int if_index);
int nl_get_phy_info(struct wphy_info *phy, unsigned int devindex);

int nl_get_frequency(uint32_t if_index);

int nl_set_channel(unsigned int if_index, int channel);

void nl_add_client(struct ether_addr* ap_mac, struct ether_addr* client_mac, uint16_t capabilitiy,
	               uint16_t aid, uint8_t *supp_rates, size_t supp_rates_len,  struct ieee80211_ht_cap *ht_cap,
	               struct ieee80211_vht_cap *vht_cap);
void nl_del_client(struct ether_addr* ap_mac, struct ether_addr* client_mac);

void nl_run_for_all_sta(struct ether_addr* bssid, for_all_clients_cb fn, void* params);

int nl_add_lvap(struct ether_addr* bssid, uint8_t* beacon_data, size_t beacon_len);
void nl_del_lvap(struct ether_addr* bssid);

void nl_init();

#endif /* NL_H */
