#include <OFConnectionManager/ofconnectionmanager_config.h>
#include <OFConnectionManager/ofconnectionmanager.h>
#include <SocketManager/socketmanager.h>

#include <indigo/of_connection_manager.h>

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <net/ethernet.h>

#include "utils.h"
#include "ieee80211.h"


#define INDENT_BUF(buf, n) char buf[n]; memset(buf, ' ', n); buf[n-1] = '\0';

static void
of_ht_cap_to_nl(of_ieee80211_ht_cap_t *in, struct ieee80211_ht_cap *out)
{
    of_ieee80211_mcs_info_t *mcs;
    of_ieee80211_mcs_rx_mask_t rx_mask;
    {
        mcs = of_ieee80211_ht_cap_mcs_get(in);
        of_ieee80211_mcs_info_rx_mask_get(mcs, &rx_mask);

        memcpy(&out->mcs.rx_mask, &rx_mask.bytes, 10);
        of_ieee80211_mcs_info_rx_highest_get(mcs, &out->mcs.rx_highest);
        of_ieee80211_mcs_info_tx_params_get(mcs, &out->mcs.tx_params);
    }
    {
        of_ieee80211_ht_cap_cap_info_get(in, &out->cap_info);
        of_ieee80211_ht_cap_ampdu_params_info_get(in, &out->ampdu_params_info);
        of_ieee80211_ht_cap_extended_ht_cap_info_get(in,
            &out->extended_ht_cap_info);
    }
}

static void
print_rates(uint32_t *rates, size_t n_rates, size_t indent_depth)
{
	INDENT_BUF(indent, indent_depth);

	printf("%sSupported rates:\n", indent);
	for (size_t i = 0; i < n_rates; i++)
		printf("%s  %2.1f Mbps\n", indent, rates[i] * 0.1);
	printf("\n");
}

static void
print_freqs(struct ieee80211_freq_info *freqs, size_t n_freqs, size_t indent_depth)
{
	INDENT_BUF(indent, indent_depth);

	printf("%sFrequencies:\n", indent);
	for (size_t i = 0; i < n_freqs; i++) {
		printf("%s  %d MHz ", indent, freqs[i].freq);
		if (freqs[i].disabled) {
			printf("(disabled)\n");
		} else {
			printf("%.1f dBm\n", 0.01 * freqs[i].max_tx_power);
		}
	}
	printf("\n");
}

static void
print_ht_capabilities(struct ieee80211_ht_cap *ht_cap, size_t indent_depth)
{
	if (!ht_cap)
		return;

	INDENT_BUF(indent, indent_depth);

    struct ieee80211_mcs_info *mcs = &ht_cap->mcs;

    printf("%sHT capabilities {\n", indent);
    printf("%s  capabilities: %04x\n", indent, ht_cap->cap_info);
	printf("%s  AMPDU parameters: %02x\n", indent, ht_cap->ampdu_params_info);
    printf("%s  MCS\n", indent);
    printf("%s    RX mask: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
    	indent, mcs->rx_mask[0], mcs->rx_mask[1],
        mcs->rx_mask[2], mcs->rx_mask[3], mcs->rx_mask[4], mcs->rx_mask[5],
        mcs->rx_mask[6], mcs->rx_mask[7], mcs->rx_mask[8], mcs->rx_mask[9]);
    printf("%s    RX highest: %04x\n", indent, mcs->rx_highest);
    printf("%s    TX parameters: %02x\n", indent, mcs->tx_params);
    printf("%s  extended HT capabilities: %04x\n", indent, ht_cap->extended_ht_cap_info);
    printf("%s  TX BF capabilities: %08x\n", indent, ht_cap->tx_BF_cap_info);
    printf("%s  Antenna selection: %02x\n", indent, ht_cap->antenna_selection_info);
    printf("%s}\n", indent);
}

static void
print_vht_capabilities(struct ieee80211_vht_cap *vht_cap, size_t indent_depth)
{
    if (!vht_cap)
    	return;

    INDENT_BUF(indent, indent_depth);

    printf(	"%sVHT capabilities:\n"
    		"%s  capabilities: %08x\n"
    		"%s  MCS\n"
    		"%s    RX MCS: %04x\n"
    		"%s    RX highest: %04x\n"
    		"%s    TX MCS: %04x\n"
    		"%s    TX highest: %04x\n", indent, indent, vht_cap->cap_info,
    		indent, indent, vht_cap->mcs.rx_vht_mcs, indent, vht_cap->mcs.rx_highest,
    		indent, vht_cap->mcs.tx_vht_mcs, indent, vht_cap->mcs.tx_highest);
}

static void
print_bands(struct ieee80211_band *band, size_t n_bands, size_t indent_depth)
{
	INDENT_BUF(indent, indent_depth);

	for (size_t i = 0; i < n_bands; i++) {
		printf(
			"%sBand %d:\n", indent,  i + 1);
		print_ht_capabilities(band[i].ht_cap, indent_depth + 2);
		print_vht_capabilities(band[i].vht_cap, indent_depth + 2);
		print_freqs(band->freqs, band->n_freqs, indent_depth + 2);
		print_rates(band->rates, band->n_rates, indent_depth + 2);
	}
}

void
_DEBUG_print_wphy(struct wphy_info *phy)
{
	printf("Wireless PHY %s(%d):\n", phy->name ? phy->name : "",
		(uint32_t) phy->id);
	print_bands(phy->bands, phy->n_bands, 1);
}

static void
print_stainfo(struct stainfo *s, size_t indent_depth)
{
	if (!s)
		return;

	INDENT_BUF(indent, indent_depth);

	printf("%sClient info:\n", indent);
	printf("%s  Mac: %s\n", indent, ether_ntoa(&s->mac));
	printf("%s  Assoc ID: %d", indent, s->assoc_id);
	printf("%s  Capabilities: %04x", indent, s->capabilities);
	printf("%s  Supported rates: %s", indent, s->supported_rates);
}

static void
print_stainfo_crypto(struct stainfo_crypto *s, size_t indent_depth)
{
	if (!s)
		return;

	INDENT_BUF(indent, indent_depth);

	print_stainfo(&s->client_info, indent_depth);
	printf("%s  Keys:\n", indent);
	printf("%s    pmk: ", indent);
	for (size_t i = 0; i < s->pmk_len; i++) {
		printf("%02x", s->pmk[i]);
	}
	printf("\n");
	printf("%s    kck: ", indent);
	for (size_t i = 0; i < s->kck_len; i++) {
		printf("%02x", s->kck[i]);
	}
	printf("\n");
	printf("%s    kek: ", indent);
	for (size_t i = 0; i < s->kek_len; i++) {
		printf("%02x", s->kek[i]);
	}
	printf("\n");
	printf("%s    tk: ", indent);
	for (size_t i = 0; i < s->tk_len; i++) {
		printf("%02x", s->tk[i]);
	}
	printf("\n");
	printf("%s    seq: ", indent);
	for (size_t i = 0; i < s->seq_len; i++) {
		printf("%02x", s->seq[i]);
	}
	printf("\n");
}

void
_DEBUG_print_station_info(union station_info *s, bool encrypted)
{
	if (encrypted) {
		print_stainfo_crypto(&s->encrypted, 1);
	} else {
		print_stainfo(&s->client_info, 1);
	}
}

/* grow buffer exponentially */
static int
buf_grow(struct info_buf *buf)
{
	buf->buf = realloc(buf->buf, 2 * INFO_BUFSIZE_BYTES(buf));
	if (!buf->buf)
		return -ENOMEM;

	buf->pos = buf->buf + buf->n_el * buf->el_size;
	buf->size *= 2;
}

int
info_buf_append(struct info_buf *buf, void *data)
{
	if (!buf->pos) {
		buf->buf = calloc(INFO_BUF_INITSIZE, buf->el_size);
		if (!buf->buf)
			return -ENOMEM;

		buf->pos = buf->buf;
		buf->size = INFO_BUF_INITSIZE;
	} else if (buf->pos >= buf->buf + INFO_BUFSIZE_BYTES(buf)) {
		if (buf_grow(buf))
			return -ENOMEM;
	}

	memcpy(buf->pos, (unsigned char*) data, buf->el_size);
	buf->pos += buf->el_size;
	buf->n_el++;

	// printf("appended data to buffer. new size: %d/%d\n", 
	// 	buf->n_el * buf->el_size, INFO_BUFSIZE_BYTES(buf));

	return 0;
}

void
info_buf_free(struct info_buf *buf)
{
	free(buf->buf);
	free(buf);
}

/* Write 0-terminated hexstring to buffer as bytes.
 * Return number of bytes written.
 */
size_t
hexparse(const char *hexstring, uint8_t *buf)
{
    const char *ptr;
    uint8_t *dest = buf;

    char chunk[3];
    chunk[2] = '\0';
    for (ptr = hexstring; *ptr && *(ptr + 1); ptr += 2) {
        chunk[0] = ptr[0];
        chunk[1] = ptr[1];
        uint8_t val = strtol(chunk, NULL, 16);
        *dest++ = val;
    }

    return dest - buf;
}

int
ieee80211_channel_to_frequency(uint8_t chan, enum nl80211_band band)
{
	/* see 802.11 17.3.8.3.2 and Annex J
	 * there are overlapping channel numbers in 5GHz and 2GHz bands */
	if (chan <= 0)
		return 0; /* not supported */
	switch (band) {
	case NL80211_BAND_2GHZ:
		if (chan == 14)
			return 2484;
		else if (chan < 14)
			return 2407 + chan * 5;
		break;
	case NL80211_BAND_5GHZ:
		if (chan >= 182 && chan <= 196)
			return 4000 + chan * 5;
		else
			return 5000 + chan * 5;
		break;
	case NL80211_BAND_60GHZ:
		if (chan < 5)
			return 56160 + chan * 2160;
		break;
	default:
		;
	}
	return 0; /* not supported */
}

int
ieee80211_frequency_to_channel(int freq)
{
	/* see 802.11-2007 17.3.8.3.2 and Annex J */
	if (freq == 2484)
		return 14;
	else if (freq < 2484)
		return (freq - 2407) / 5;
	else if (freq >= 4910 && freq <= 4980)
		return (freq - 4000) / 5;
	else if (freq <= 45000) /* DMG band lower limit */
		return (freq - 5000) / 5;
	else if (freq >= 58320 && freq <= 64800)
		return (freq - 56160) / 2160;
	else
		return 0;
}

void
_DEBUG_print_sdwn_nic_entity(void *arg)
{
	of_sdwn_entity_nic_t *nic = (of_sdwn_entity_nic_t*) arg;

    of_mac_addr_t bssid = {
        .addr = {0, 0, 0, 0, 0, 0},
    };

    of_sdwn_entity_nic_mac_addr_get(nic, &bssid);
    
    printf("NIC {\n"
        "\tBSSID: %s\n"
        "}\n",
        ether_ntoa((struct ether_addr*) &bssid));
}

void
_DEBUG_print_sdwn_accesspoint_entity(void *arg)
{
	of_sdwn_entity_accesspoint_t *ap = (of_sdwn_entity_accesspoint_t*) arg;

    of_mac_addr_t bssid = {
        .addr = {0, 0, 0, 0, 0, 0},
    };
    of_port_name_t ap_name;
    of_octets_t ssid;
    of_sdwn_entity_accesspoint_bssid_get(ap, &bssid);
    of_sdwn_entity_accesspoint_name_get(ap, &ap_name);
    of_sdwn_entity_accesspoint_ssid_get(ap, &ssid);

    char ssid_buf[ssid.bytes + 1];
    strncpy(ssid_buf, ssid.data, ssid.bytes);
    ssid_buf[ssid.bytes] = '\0';

    printf("ACCESS POINT {\n"
        "\tName: %s\n"
        "\tBSSID: %s\n"
        "\tSSID: %s\n"
        "}\n",
        ap_name, ether_ntoa((struct ether_addr*) &bssid), ssid_buf);
}

void
_DEBUG_print_sdwn_related_switch_entity(void *arg)
{
	of_sdwn_entity_related_switch_t *sw = (of_sdwn_entity_related_switch_t*) arg;
    uint64_t dpid;
    of_sdwn_entity_related_switch_datapath_id_get(sw, &dpid);

    printf("RELATED OF SWITCH {\n"
        "\tDATAPATH ID: %08" PRIx64 "\n"
        "}\n", dpid);
}

static void
print_frequency_band_entity(of_sdwn_entity_band_t* band, size_t indent_depth)
{

	if (!band)
		return;

	INDENT_BUF(indent, indent_depth);

	uint16_t band_no, cap_flags;
	of_ieee80211_ht_cap_t *of_ht_cap;
	// of_ieee80211_vht_cap_t *of_vht_cap;

	struct ieee80211_ht_cap ht_cap;
	// ieee80211_vht_cap vht_cap;

	of_sdwn_entity_band_band_no_get(band, &band_no);
	of_sdwn_entity_band_cap_flags_get(band, &cap_flags);

	printf("%sFREQUENCY BAND {\n"
		"%s  NUMBER: %d\n", indent, indent, band_no);

	if (IEEE80211_CAPABILITY_FLAG_HT_CAP_SET(cap_flags, OF_VERSION_1_3)) {
		of_ht_cap = of_sdwn_entity_band_ht_capabilities_get(band);
		of_ht_cap_to_nl(of_ht_cap, &ht_cap);
		print_ht_capabilities(&ht_cap, indent_depth + 1);
	}

	// if (IEEE80211_CAPABILITY_FLAG_VHT_CAP_SET(cap_flags, OF_VERSION_1_3)) {
	// 	vht_cap = of_sdwn_entity_band_vht_capabilities_get(band);
	// 	of_vht_cap_to_loci(of_vht_cap, &vht_cap);
	// 	print_vht_capabilities(&vht_cap, 1);
	// }

	printf("}\n");
}

static void
print_frequency_entity(of_sdwn_entity_freq_t *freq, size_t indent_depth)
{
	if (!freq)
		return;

	INDENT_BUF(indent, indent_depth);

	uint32_t index, f, max_tx_power;
	uint16_t band_no;

	of_sdwn_entity_freq_index_get(freq, &index);
	of_sdwn_entity_freq_band_no_get(freq, &band_no);
	of_sdwn_entity_freq_freq_get(freq, &f);
	of_sdwn_entity_freq_max_tx_power_get(freq, &max_tx_power);

	printf("%sFREQUENCY {\n", indent);
	printf("%s  INDEX: %d\n", indent, index);
	printf("%s  BAND NUMBER: %d\n", indent, band_no);
	printf("%s  FREQUENCY: %d\n", indent, f);
	printf("%s  MAX TX POWER: %d\n", indent, max_tx_power);
	printf("%s}\n", indent);
}

void
_DEBUG_print_sdwn_entities(void *arg)
{
	of_list_sdwn_entity_t *list = (of_list_sdwn_entity_t*) arg;
    of_sdwn_entity_t cur;
    of_object_id_t id;
    int ret;

    OF_LIST_SDWN_ENTITY_ITER(list, &cur, ret) {
        of_sdwn_entity_wire_object_id_get(&cur, &id);
        switch (id) {
            case OF_SDWN_ENTITY_ACCESSPOINT:
                _DEBUG_print_sdwn_accesspoint_entity(
                    (of_sdwn_entity_accesspoint_t*) &cur);
                break;
            case OF_SDWN_ENTITY_NIC:
                _DEBUG_print_sdwn_nic_entity((of_sdwn_entity_nic_t*) &cur);
                break;
            case OF_SDWN_ENTITY_RELATED_SWITCH:
                _DEBUG_print_sdwn_related_switch_entity(
                    (of_sdwn_entity_related_switch_t*) &cur);
                break;
            case OF_SDWN_ENTITY_BAND:
            	print_frequency_band_entity((of_sdwn_entity_band_t*) &cur, 1);
            	break;
            case OF_SDWN_ENTITY_FREQ:
            	print_frequency_entity((of_sdwn_entity_freq_t*) &cur, 1);
            	break;
        }
    }       
}
