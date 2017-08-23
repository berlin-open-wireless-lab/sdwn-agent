#ifndef __IEEE80211
#define __IEEE80211

#include <inttypes.h>

/* 802.11n HT capability AMPDU settings (for ampdu_params_info) */
#define IEEE80211_HT_AMPDU_PARM_FACTOR          0x03
#define IEEE80211_HT_AMPDU_PARM_DENSITY         0x1C

#define IEEE80211_HT_CAP_SUP_WIDTH_20_40        0x0002
#define IEEE80211_HT_CAP_SGI_40                 0x0040
#define IEEE80211_HT_CAP_MAX_AMSDU              0x0800

#define IEEE80211_HT_MCS_MASK_LEN               10

/**
 * struct ieee80211_mcs_info - MCS information
 * @rx_mask: RX mask
 * @rx_highest: highest supported RX rate. If set represents
 *      the highest supported RX data rate in units of 1 Mbps.
 *      If this field is 0 this value should not be used to
 *      consider the highest RX data rate supported.
 * @tx_params: TX parameters
 */
struct ieee80211_mcs_info {
	uint8_t rx_mask[IEEE80211_HT_MCS_MASK_LEN];
	uint16_t rx_highest;
	uint8_t tx_params;
	uint8_t reserved[3];
} __attribute__ ((packed));

/**
 * struct ieee80211_ht_cap - HT capabilities
 *
 * This structure is the "HT capabilities element" as
 * described in 802.11n D5.0 7.3.2.57
 */
struct ieee80211_ht_cap {
	uint16_t cap_info;
	uint8_t ampdu_params_info;

	/* 16 bytes MCS information */
	struct ieee80211_mcs_info mcs;

	uint16_t extended_ht_cap_info;
	uint32_t tx_BF_cap_info;
	uint8_t antenna_selection_info;
} __attribute__ ((packed));

/**
 * struct ieee80211_vht_mcs_info - MCS information
 */
struct ieee80211_vht_mcs_info {
	uint16_t rx_vht_mcs;
	uint16_t rx_highest;
	uint16_t tx_vht_mcs;
	uint16_t tx_highest;
} __attribute__ ((packed));

/**
 * struct ieee80211_vht_cap - VHT capabilities
 *
 * This structure is the "VHT capabilities element" as
 * described in 802.11ac
 */
struct ieee80211_vht_cap {
	uint32_t cap_info;
	struct ieee80211_vht_mcs_info mcs;
} __attribute__ ((packed));

struct ieee80211_info_elmt_hdr {
	uint8_t id;
	uint8_t len;
} __attribute__ ((packed));

struct ieee80211_ssid_element {
	struct ieee80211_info_elmt_hdr hdr;
	uint8_t *octets;
} __attribute__ ((packed));

struct ieee80211_supported_rates_element {
	struct ieee80211_info_elmt_hdr hdr;
	uint8_t *rates;
} __attribute__ ((packed));

struct ieee80211_freqhop_element {
	struct ieee80211_info_elmt_hdr hdr;
	uint16_t dwell_time;
	uint8_t hop_set;
	uint8_t hop_pattern;
	uint8_t hop_index;
} __attribute__ ((packed));

struct ieee80211_dsss_element {
	struct ieee80211_info_elmt_hdr hdr;
	uint8_t curr_chan;
} __attribute__ ((packed));

struct ieee80211_cf_element {
	struct ieee80211_info_elmt_hdr hdr;
	uint8_t cfp_cnt;
	uint8_t cfp_period;
	uint16_t cfp_max_duration;
	uint16_t cfp_dur_remaining;
} __attribute__ ((packed));

struct ieee80211_header {
	uint16_t frame_ctl;
	uint16_t duration;
	struct ether_addr d_addr;
	struct ether_addr s_addr;
	struct ether_addr addr_3;
	uint16_t seq_ctl;
	uint32_t ht_ctl;
};

/* Beacon frame body up to the TIM IE. 
 * To be used with NL80211_ATTR_BEACON_HEAD when adding an LVAP */
struct ieee80211_beacon_head {
	/* frame body */
	uint64_t timestamp;
	uint16_t beacon_interval;
	uint16_t cap_info;
	struct ieee80211_ssid_element ssid;
	struct ieee80211_supported_rates_element supported_rates;
	struct ieee80211_freqhop_element fh_params;
	struct ieee80211_dsss_element dsss_params;
	struct ieee80211_cf_element cf_params;
} __attribute__ ((packed));

inline void
ieee80211_ssid_ie_init(struct ieee80211_ssid_element *ie, char *ssid)
{
	size_t ssid_len = strlen(ssid);

	ie->hdr.id = 0;
	ie->hdr.len = 2 + ssid_len;
	ie->octets = malloc(ssid_len);
	if (ie->octets)
		memcpy(ie->octets, ssid, ssid_len);
}

inline void
ieee80211_ssid_ie_free(struct ieee80211_ssid_element *ie)
{
	if (ie->octets)
		free(ie->octets);
	free(ie);
}

inline void
ieee80211_supported_rates_ie_init(struct ieee80211_supported_rates_element *ie,
		uint8_t *rates, size_t n)
{
	ie->hdr.id = 1;
	ie->hdr.len = 2 + n;
	ie->rates = malloc(n);
	if (ie->rates)
		memcpy(ie->rates, rates, n);
}

inline void
ieee80211_supported_rates_ie_free(struct ieee80211_supported_rates_element *ie)
{
	if (ie->rates)
		free(ie->rates);
	free(ie);
}

inline void
ieee80211_freqhop_ie_init(struct ieee80211_freqhop_element *ie,
		uint16_t dwell_time, uint8_t hop_set, uint8_t hop_pattern,
		uint8_t hop_index)
{
	ie->hdr.id = 2;
	ie->hdr.len = 5;
	ie->dwell_time = dwell_time;
	ie->hop_set = hop_set;
	ie->hop_pattern = hop_pattern;
	ie->hop_index = hop_index;
}

inline void
ieee80211_dsss_ie_init(struct ieee80211_dsss_element *ie, uint8_t chan)
{
	ie->hdr.id = 3;
	ie->hdr.len = 3;
	ie->curr_chan = chan;
}

inline void
ieee80211_cf_ie_init(struct ieee80211_cf_element *ie, uint8_t cfp_cnt,
		uint8_t cfp_period, uint16_t cfp_max_duration,
		uint16_t cfp_dur_remaining)
{
	ie->hdr.id = 4;
	ie->hdr.len = 8;
	ie->cfp_cnt = cfp_cnt;
	ie->cfp_period = cfp_period;
	ie->cfp_max_duration = cfp_max_duration;
	ie->cfp_dur_remaining = cfp_dur_remaining;
}

inline void
ieee80211_beacon_head_free(struct ieee80211_beacon_head *beacon)
{
	if (beacon->ssid.octets)
		free(beacon->ssid.octets);

	if (beacon->supported_rates.rates)
		free(beacon->supported_rates.rates);

	free(beacon);
}

#endif /* __IEEE80211 */
