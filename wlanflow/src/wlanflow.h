#ifndef WLANFLOW_H_
#define WLANFLOW_H_

#include <stdbool.h>
#include <netinet/ether.h>

#include "ieee80211.h"

struct stainfo_lvap {
	struct ether_addr mac;
};

struct stainfo {
	struct ether_addr mac;
	uint32_t assoc_id;
	uint16_t capabilities;
	char *supported_rates;
	struct ieee80211_ht_cap *ht_cap;
};

struct stainfo_crypto {
	struct stainfo client_info;

	size_t pmk_len, kck_len, kek_len, tk_len;
	uint8_t *pmk, *kck, *kek, *tk;
	size_t seq_len;
	uint8_t *seq;
};

union station_info {
	struct stainfo_lvap lvap;
	struct stainfo client_info;
	struct stainfo_crypto encrypted;
};

struct ieee80211_freq_info {
	uint32_t freq;
	uint32_t max_tx_power; 	// in dBm, to be multiplied by 0.01
	bool disabled;
};

struct ieee80211_band {
	struct ieee80211_ht_cap *ht_cap;
	struct ieee80211_vht_cap *vht_cap;
	struct ieee80211_freq_info *freqs;
	size_t n_freqs;
	uint32_t *rates;		// to be multiplied by 0.1
	size_t n_rates;
};

struct wphy_info {
	int64_t id;
	char *name;
	struct ieee80211_band *bands;
	size_t n_bands;
};

struct ap_info {
	char *name;
	unsigned int ifindex;
	struct ether_addr bssid;
	bool encrypted;
	size_t ssid_len;
	unsigned char ssid[32];
};

struct wdev_info {
	char *name;
	bool up;
	bool disabled;
	uint16_t channel;
	char *path;
	struct ether_addr mac;
	struct ap_info *aps;
	size_t n_aps;
};

inline void
wlanflow_ap_info_free(struct ap_info *ap)
{
	if (ap->name)
		free(ap->name);
	free(ap);
}

inline void
wlanflow_wdev_info_free(struct wdev_info *wdev)
{
	if (wdev->path)
		free(wdev->path);

	for (size_t i = 0; i < wdev->n_aps; i++)
		wlanflow_ap_info_free(&wdev->aps[i]);
}

inline void
ieee80211_band_free(struct ieee80211_band *band)
{
	size_t i;

	for (i = 0; i < band->n_freqs; i++)
		free(&band->freqs[i]);

	for (i = 0; i < band->n_rates; i++)
		free(&band->rates[i]);

	free(band);
}

inline void
wphy_info_free(struct wphy_info *phy, bool static_alloc)
{
	if (phy->name)
		free(phy->name);

	for (size_t i = 0; i < phy->n_bands; i++) {
		free(phy->bands[i].freqs);
		free(phy->bands[i].rates);
	}

	free(phy->bands);

	if (!static_alloc)
		free(phy);
}

enum {
	FOR_ALL_CLIENTS_CB_STATUS_CONTINUE,
	FOR_ALL_CLIENTS_CB_STATUS_STOP,
};

/* Callback function to be called with ubus_run_for_all_sta. last indicates whether the callback
 * is the last one to be called in the current run. This is useful for multipart replies, because
 * it allows to set the MORE flag in all but the last message.
 * The callback can also signal whether to call it again with the next STA by returning
 * FOR_ALL_STA_CB_STATUS_CONTINUE or to stop by returning FOR_ALL_STA_CB_STATUS_STOP.
 */
typedef int (for_all_clients_cb)(union station_info*, bool last, void*);
// typedef void (for_all_sta_err_cb)(void*);

int wf_add_client(uint32_t if_no, struct ether_addr* client_mac, const char *if_name);
void wf_del_client(uint32_t if_no, struct ether_addr* client_mac, const char *if_name);

void wlanflow_start_timeout(void (*handler)(void*), void *cookie, int timeout);
void wlanflow_stop_timeout(void (*handler)(void*), void *cookie);

int wlanflow_reload(void);
int wlanflow_register_fd(int fd, void (*handler)(int socket_id, void *data,
                         int read_ready, int write_ready, int err), void *cookie);

#endif