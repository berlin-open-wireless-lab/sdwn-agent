#include <OFConnectionManager/ofconnectionmanager_config.h>
#include <OFConnectionManager/ofconnectionmanager.h>
#include <SocketManager/socketmanager.h>

#include <net/if.h>

#include <indigo/assert.h>

#include <linux/nl80211.h>

#include "nl.h"
#include "ubus.h"
#include "connection.h"
#include "mon.h"
#include "sysfs.h"
#include "wlanflow.h"
#include "utils.h"


struct cb_args_of {
    uint32_t xid;
    indigo_cxn_id_t cxn_id;
    of_version_t of_version;
    bool encrypted;
};


static of_ieee80211_ht_cap_t*
ieee_ht_caps_to_of(struct ieee80211_ht_cap *ht, of_version_t of_version)
{
    of_ieee80211_ht_cap_t *of = of_ieee80211_ht_cap_new(of_version);
    of_ieee80211_mcs_info_t *mcs = of_ieee80211_mcs_info_new(of_version);
    of_ieee80211_mcs_rx_mask_t rx_mask;

    if (!of || !mcs)
        return NULL;

    memcpy(&rx_mask, ht->mcs.rx_mask, IEEE80211_HT_MCS_MASK_LEN);
    of_ieee80211_mcs_info_rx_mask_set(mcs, rx_mask);
    of_ieee80211_mcs_info_rx_highest_set(mcs, ht->mcs.rx_highest);
    of_ieee80211_mcs_info_tx_params_set(mcs, ht->mcs.tx_params);
    of_ieee80211_vht_cap_cap_info_set(of, ht->cap_info);
    of_ieee80211_ht_cap_extended_ht_cap_info_set(of, ht->extended_ht_cap_info);
    of_ieee80211_ht_cap_tx_BF_cap_info_set(of, ht->tx_BF_cap_info);
    of_ieee80211_ht_cap_antenna_selection_info_set(of,
            ht->antenna_selection_info);

    return of;
}

static void
send_client_info_lvap(union station_info *s, bool last, struct cb_args_of *args)
{
    // TODO
    uint16_t flags = 0;
    struct stainfo_lvap *client = (struct stainfo_lvap*) s;
    of_sdwn_get_clients_reply_t *reply =
        of_sdwn_get_clients_reply_lvap_new(args->of_version);

    if (!reply)
        return;

    if (!last)
        OF_STATS_REPLY_FLAG_REPLY_MORE_SET(args->of_version, flags);

    of_sdwn_get_clients_reply_lvap_mac_set(reply,
                                        *(of_mac_addr_t*) &client->mac);

    of_sdwn_get_clients_reply_lvap_xid_set(reply, args->xid);
    of_sdwn_get_clients_reply_lvap_flags_set(reply, flags);

    indigo_cxn_send_controller_message(args->cxn_id, reply);
}

static int
send_client_info(union station_info *sta, bool last, void *arg)
{
    printf("call :: %s\n", __func__);

    struct cb_args_of *args = arg;

    conn_send_get_clients_reply(args->cxn_id, args->of_version, args->xid, sta,
                             args->encrypted, !last);

    return FOR_ALL_CLIENTS_CB_STATUS_CONTINUE;
}

int
conn_handle_sdwn_get_remote_port_req(indigo_cxn_id_t cxn_id,
    of_sdwn_get_remote_port_request_t *req)
{
    of_sdwn_get_remote_port_reply_t *reply;
    uint32_t xid;
    uint16_t flags = 0;

    of_sdwn_get_remote_port_request_xid_get(req, &xid);

    if ((reply = of_sdwn_get_remote_port_reply_new(req->version)) == NULL) {
        printf("Could not allocate config response obj\n");
        return -1;
    }

    of_sdwn_get_remote_port_reply_xid_set(reply, xid);
    of_sdwn_get_remote_port_reply_if_no_set(reply, remote_port);
    indigo_cxn_send_controller_message(cxn_id, reply);

    return 0;
}

int
conn_handle_sdwn_add_client_cmd(indigo_cxn_id_t cxn_id, of_sdwn_add_client_t *cmd)
{
    int rv, ret;
    size_t keycount = 0;
    uint32_t xid;
    of_mac_addr_t client_mac;
    of_port_no_t if_no;
    uint16_t assoc_id, capabilities = 0;
    union station_info si;
    struct stainfo *client_info;
    bool encrypted;

    of_ieee80211_ht_cap_t *ht_cap;
    of_ieee80211_vht_cap_t *vht_cap;
    of_desc_str_t supported_rates_string;

    of_sdwn_add_client_xid_get(cmd, &xid);
    of_sdwn_add_client_client_get(cmd, &client_mac);
    of_sdwn_add_client_ap_get(cmd, &if_no);
    of_sdwn_add_client_assoc_id_get(cmd, &assoc_id);
    ht_cap = of_sdwn_add_client_ht_capabilities_get(cmd);
    vht_cap = of_sdwn_add_client_vht_capabilities_get(cmd);
    of_sdwn_add_client_supported_rates_get(cmd, &supported_rates_string);

    char ifname[IF_NAMESIZE + 1];
    printf("adding client %s to %s ", ether_ntoa((struct ether_addr*) &client_mac),
        if_indextoname(if_no, ifname));

    of_list_bsn_tlv_data_t *keylist = of_sdwn_add_client_keys_get(cmd);

    of_bsn_tlv_data_t listentry;
    of_octets_t keys[5]; // keys in order pmk, kck, kek, tk, seq

    OF_LIST_BSN_TLV_DATA_ITER(keylist, &listentry, rv) {
        of_bsn_tlv_data_value_get(&listentry, &keys[keycount % 5]);
        keycount++;
    }

    encrypted = keycount == 5;

    if (encrypted) {
        client_info = &si.encrypted.client_info;
        struct stainfo_crypto *sic = &si.encrypted;
        sic->pmk = keys[0].data;
        sic->kck = keys[1].data;
        sic->kek = keys[2].data;
        sic->tk  = keys[3].data;

        sic->pmk_len = keys[0].bytes;
        sic->kck_len = keys[1].bytes;
        sic->kek_len = keys[2].bytes;
        sic->tk_len  = keys[3].bytes;

        sic->seq = keys[4].data;
        sic->seq_len = keys[4].bytes;
    } else {
        client_info = &si.client_info;
    }

    memcpy(&client_info->mac, &client_mac, ETH_ALEN);

    return ubus_add_client(if_no, &si, encrypted);
    /* TODO! implement non-ubus STAs
    } else {
        // TODO! translate loci capability types to nl80111.h types
        struct ieee80211_ht_cap nl_ht_cap;
        struct ieee80211_vht_cap nl_vht_cap;

        // uint8_t ht_capabilities[26];
        // uint8_t supported_rates[12];
        uint8_t supported_rates[NL80211_MAX_SUPP_RATES];
 
        if (strlen(supported_rates_string) > 2 * NL80211_MAX_SUPP_RATES) {
            printf("supported rates string too long!\n");
            return -1;
        }
 
        size_t supported_rates_len = hexparse(supported_rates_string,
            supported_rates);

        printf("supported rates string: %s\n", supported_rates_string);

        nl_add_sta((struct ether_addr*) &ap, (struct ether_addr*) &client_mac, 
            capabilities, assoc_id, supported_rates, supported_rates_len, 
            &nl_ht_cap, &nl_vht_cap);
    }*/
}

int
conn_handle_sdwn_del_client_cmd(indigo_cxn_id_t cxn_id, of_sdwn_del_client_t *cmd)
{
    uint32_t xid;
    of_mac_addr_t client;
    of_port_no_t if_no;
    char ifname[IF_NAMESIZE + 1];
    uint16_t reason;
    bool deauth;
    uint32_t ban_time;
    int ret;

    of_sdwn_del_client_xid_get(cmd, &xid);
    of_sdwn_del_client_client_get(cmd, &client);
    of_sdwn_del_client_ap_get(cmd, &if_no);
    of_sdwn_del_client_reason_get(cmd, &reason);
    of_sdwn_del_client_deauth_get(cmd, (uint8_t*) &deauth);
    of_sdwn_del_client_ban_time_get(cmd, &ban_time);

    printf("supposed to delete client %s on ap %s\n",
        ether_ntoa((struct ether_addr*) &client), if_indextoname(if_no, ifname));

    return ubus_del_client(if_no, (struct ether_addr*) &client,
                       reason, deauth, ban_time);

    // TODO
    // nl_del_client((struct ether_addr*) &ap, (struct ether_addr*) &client);
}

int
conn_handle_sdwn_get_clients_req(indigo_cxn_id_t cxn_id,
    of_sdwn_get_clients_request_t *req)
{
    of_sdwn_get_clients_reply_t *reply;
    uint32_t xid, chan;
    of_port_no_t if_no;
    int ret;

    for_all_clients_cb *cb;
    struct cb_args_of args;
 
    of_sdwn_get_clients_request_xid_get(req, &xid);
    of_sdwn_get_clients_request_if_no_get(req, &if_no);

    ret = ubus_get_ctx_for_if(NULL, if_no, &chan, (int*) &args.cxn_id,
                              (int*) &args.of_version, &args.encrypted);
    if (ret) {
        fprintf(stderr, "No monitoring context found for interface %d\n",if_no);
        return -1;
    }

    args.xid = xid;

    ubus_run_for_all_clients(if_no, send_client_info, &args);

    return 0;
}

int
conn_handle_sdwn_add_lvap_cmd(indigo_cxn_id_t cxn_id, of_sdwn_add_lvap_t *cmd)
{
    printf("call :: %s\n", __func__);

    of_mac_addr_t bssid;
    struct ieee80211_beacon_head *beacon;
    char *test_ssid = "===>TEST<===";
    uint8_t test_rates[2] = {0xaa, 0xbb};

    size_t beacon_len;
    unsigned char *beacon_buf;

    of_sdwn_add_lvap_bssid_get(cmd, &bssid);

    if (nl_add_lvap((struct ether_addr*) &bssid, beacon_buf, beacon_len)) {
        // respond with error message
    }

    ieee80211_beacon_head_free(beacon);
    free(beacon_buf);

    return 0;
}

int
conn_handle_sdwn_del_lvap_cmd(indigo_cxn_id_t cxn_id, of_sdwn_del_lvap_t *cmd)
{
    uint32_t xid;
    uint16_t flags = 0;
    of_mac_addr_t bssid;
 
    of_sdwn_del_lvap_xid_get(cmd, &xid);
    of_sdwn_del_lvap_bssid_get(cmd, &bssid);

    nl_del_lvap((struct ether_addr*) &bssid);

    return 0;
}

int
conn_handle_sdwn_get_channel_req(indigo_cxn_id_t cxn_id,
        of_sdwn_get_channel_request_t *req)
{
    uint32_t chan;
    int of_version, ret;
    bool encrypted;
    uint32_t xid;
    of_port_no_t if_index;
    of_sdwn_get_channel_reply_t *reply;

    of_sdwn_get_channel_request_if_no_get(req, &if_index);
    of_sdwn_get_channel_request_xid_get(req, &xid);

    char if_name[IF_NAMESIZE + 1];
    memset(if_name, 0, IF_NAMESIZE + 1);
    if (!if_indextoname(if_index, if_name))
        return -1;

    ret = ubus_get_ctx_for_if(if_name, 0, &chan, &cxn_id, &of_version,
                              &encrypted);
    if (ret)
        return -1;

    reply = of_sdwn_get_channel_reply_new(of_version);
    if (reply)
        return -1;

    of_sdwn_get_channel_reply_xid_set(reply, xid);
    of_sdwn_get_channel_reply_channel_set(reply, chan);

    indigo_cxn_send_controller_message(cxn_id, reply);

    return 0;
}

int
conn_handle_sdwn_set_channel_cmd(indigo_cxn_id_t cxn_id,
        of_sdwn_set_channel_t *cmd)
{
    uint32_t freq, bcn_count, if_index;
    int ret;

    of_sdwn_set_channel_frequency_get(cmd, &freq);
    of_sdwn_set_channel_if_no_get(cmd, &if_index);
    of_sdwn_set_channel_beacon_count_get(cmd, &bcn_count);

    ret = ubus_set_channel(if_index, freq, bcn_count);
    if (ret) {
        fprintf(stderr, "Failed to set channel\n");
        return ret;
    }

    of_sdwn_set_channel_t *reply = of_sdwn_set_channel_new(cmd->version);
    if (!reply)
        return -1;
    
    of_sdwn_set_channel_frequency_set(reply, freq);
    of_sdwn_set_channel_if_no_set(reply, if_index);
    of_sdwn_set_channel_beacon_count_set(reply, bcn_count);

    indigo_cxn_send_controller_message(cxn_id, reply);
    // nl_set_channel(if_index, ieee80211_frequency_to_channel(freq));
}

static void
loci_ht_cap_to_nl(of_ieee80211_ht_cap_t *in, struct ieee80211_ht_cap *out)
{
    of_ieee80211_mcs_info_t *mcs;
    of_ieee80211_mcs_rx_mask_t rx_mask;
    {
        mcs = of_ieee80211_ht_cap_mcs_get(in);
        of_ieee80211_mcs_info_rx_mask_get(in, &rx_mask);

        memcpy(&out->mcs.rx_mask, &rx_mask.bytes, 10);
        of_ieee80211_mcs_info_rx_highest_get(in, &out->mcs.rx_highest);
        of_ieee80211_mcs_info_tx_params_get(in, &out->mcs.tx_params);
    }
    {
        of_ieee80211_ht_cap_cap_info_get(in, &out->cap_info);
        of_ieee80211_ht_cap_ampdu_params_info_get(in, &out->ampdu_params_info);
        of_ieee80211_ht_cap_extended_ht_cap_info_get(in,
            &out->extended_ht_cap_info);
    }
}

/* translate ieee80211_ht_cap structs from ieee80211.h to loci type */
static of_ieee80211_ht_cap_t*
ht_cap_to_loci(struct ieee80211_ht_cap *in, of_version_t version)
{
    of_ieee80211_mcs_info_t *mcs = of_ieee80211_mcs_info_new(version);
    of_ieee80211_ht_cap_t *out = of_ieee80211_ht_cap_new(version);
    if (!out || !mcs)
        return NULL;
    {
        of_ieee80211_mcs_rx_mask_t rx_mask;
        memcpy(&rx_mask, in->mcs.rx_mask, 10);
        of_ieee80211_mcs_info_rx_highest_set(mcs, in->mcs.rx_highest);
        of_ieee80211_mcs_info_tx_params_set(mcs, in->mcs.tx_params);
    }
    {
        of_ieee80211_ht_cap_cap_info_set(out, in->cap_info);
        of_ieee80211_ht_cap_ampdu_params_info_set(out, in->ampdu_params_info);
        of_ieee80211_ht_cap_mcs_set(out, mcs);
        of_ieee80211_ht_cap_extended_ht_cap_info_set(out,
            in->extended_ht_cap_info);
        of_ieee80211_ht_cap_antenna_selection_info_set(out,
            in->antenna_selection_info);
    }

    return out;
}

/* translate ieee80211_vht_cap structs from ieee80211.h to loci type */
static of_ieee80211_vht_cap_t*
vht_cap_to_loci(struct ieee80211_vht_cap *in, of_version_t version)
{
    of_ieee80211_vht_mcs_info_t *mcs = of_ieee80211_vht_mcs_info_new(version);
    of_ieee80211_vht_cap_t *out = of_ieee80211_vht_cap_new(version);
    if (!out || !mcs)
        return NULL;

    {
        of_ieee80211_vht_mcs_info_rx_vht_mcs_set(mcs, in->mcs.rx_vht_mcs);
        of_ieee80211_vht_mcs_info_rx_highest_set(mcs, in->mcs.rx_highest);
        of_ieee80211_vht_mcs_info_tx_vht_mcs_set(mcs, in->mcs.tx_vht_mcs);
        of_ieee80211_vht_mcs_info_tx_highest_set(mcs, in->mcs.tx_highest);
    }
    {
        of_ieee80211_vht_cap_cap_info_set(out, in->cap_info);
        of_ieee80211_vht_cap_mcs_set(out, mcs);
    }

    return out;
}

static int
add_rate(of_list_sdwn_entity_t *list, uint32_t rate, uint32_t phy_devindex,
        uint16_t band_no, of_version_t version)
{
    of_sdwn_entity_rate_t *rate_entity = of_sdwn_entity_rate_new(version);
    if (!rate_entity)
        return -1;

    of_sdwn_entity_rate_index_set(rate_entity, phy_devindex);
    of_sdwn_entity_rate_band_no_set(rate_entity, band_no);
    of_sdwn_entity_rate_rate_set(rate_entity, rate);

    return of_list_sdwn_entity_append(list, rate_entity);
}

static int
add_freq(of_list_sdwn_entity_t *list, struct ieee80211_freq_info *freq,
        uint32_t phy_devindex, uint16_t band_no, of_version_t version)
{
    of_sdwn_entity_freq_t *freq_entity = of_sdwn_entity_freq_new(version);
    if (!freq_entity)
        return -1;

    of_sdwn_entity_freq_index_set(freq_entity, phy_devindex);
    of_sdwn_entity_freq_band_no_set(freq_entity, band_no);
    of_sdwn_entity_freq_freq_set(freq_entity, freq->freq);
    of_sdwn_entity_freq_max_tx_power_set(freq_entity, freq->max_tx_power);

    return of_list_sdwn_entity_append(list, freq_entity);
}

static int
add_band(of_list_sdwn_entity_t *list, struct ieee80211_band *band,
        uint32_t phy_devindex, uint16_t band_no, of_version_t version)
{
    uint16_t cap_flags = 0;
    of_ieee80211_ht_cap_t *ht_cap;
    of_ieee80211_vht_cap_t *vht_cap;

    of_sdwn_entity_band_t *b_entity = of_sdwn_entity_band_new(version);
    if (!b_entity)
        return -1;

    if (band->ht_cap) {
        IEEE80211_CAPABILITY_FLAG_HT_CAP_SET(cap_flags, version);
        ht_cap = ht_cap_to_loci(band->ht_cap, version);
        of_sdwn_entity_band_ht_capabilities_set(b_entity, ht_cap);
    }

    if (band->vht_cap) {
        IEEE80211_CAPABILITY_FLAG_VHT_CAP_SET(cap_flags, version);
        vht_cap = vht_cap_to_loci(band->vht_cap, version);
        of_sdwn_entity_band_vht_capabilities_set(b_entity, vht_cap);
    }

    of_sdwn_entity_band_index_set(b_entity, phy_devindex);
    of_sdwn_entity_band_band_no_set(b_entity, band_no);
    of_sdwn_entity_band_cap_flags_set(b_entity, cap_flags);

    of_list_sdwn_entity_append(list, b_entity);

    for (size_t i = 0; i < band->n_freqs; i++) {
        if (band->freqs[i].disabled)
            continue;
        add_freq(list, &band->freqs[i], phy_devindex, band_no, version);
    }

    for (size_t i = 0; i < band->n_rates; i++)
        add_rate(list, band->rates[i], phy_devindex, band_no, version);

    return 0;
}

static int
add_nic(of_list_sdwn_entity_t *list, struct wdev_info *wdev,
        of_version_t version)
{
    of_sdwn_entity_nic_t *nic = NULL;
    char *phy_name;
    struct wphy_info phy; 
    int64_t index;
    of_mac_addr_t mac_addr;
    int ret;

    ret = sysfs_path_to_mac(wdev->path, &wdev->mac);
    if (ret) {
        fprintf(stderr, "Failed to get MAC address using device path %s\n",
                wdev->path);
        return ret;
    }
    memcpy(&mac_addr.addr, &wdev->mac.ether_addr_octet, OF_MAC_ADDR_BYTES);

    phy_name = sysfs_path_to_phy_name(wdev->path);
    if (!phy_name) {
        fprintf(stderr, "Failed to get phy name for '%s'\n", wdev->path);
        return -1;
    }

    index = sysfs_phy_name_to_phy_index(phy_name);
    if (index < 0) {
        ret = -1;
        goto out;
    }

    ret = nl_get_phy_info(&phy, (uint32_t) index);
    if (ret) {
        fprintf(stderr, "Failed to get phy info from cfg80211 for '%s'\n", phy_name);
        goto out;
    }

    if ((nic = of_sdwn_entity_nic_new(version)) == NULL) {
        printf("Failed to allocate NIC entity object\n");
        ret = -1;
        goto out_free_phy;
    }

    of_sdwn_entity_nic_mac_addr_set(nic, mac_addr);

    for (size_t i = 0; i < phy.n_bands; i++) {
        ret = add_band(list, &phy.bands[i], (uint32_t) index, (uint16_t) i,
                    version);
        if (ret)
            goto out_free_phy;
    }

    of_list_sdwn_entity_append(list, nic);

out_free_phy:
    wphy_info_free(&phy, true);

out:
    free(phy_name);
    return ret;
}

static of_sdwn_entity_accesspoint_t*
ap_info_to_of(struct wdev_info *wdev, struct ap_info *ap,
        of_version_t version)
{
    of_sdwn_entity_accesspoint_t *ap_entity;
    struct ether_addr bssid;
    of_octets_t of_ssid;
    of_mac_addr_t of_bssid, of_phy_mac;
    uint16_t ap_config = 0;
    unsigned int if_index = 0;
    int ret, freq = 0;

    if (!ap)
        return NULL;

    ap_entity = of_sdwn_entity_accesspoint_new(version);

    if (!ap_entity)
        goto out_of_mem;

    /* if the AP is on a disabled device, it will not have an interface index
     * and no BSSID
     */
    if (wdev->disabled) {
        memset(&bssid, 0, sizeof(struct ether_addr));
    } else {

        if_index = if_nametoindex(ap->name);
        if (!if_index)
            goto error;

        ret = nl_get_mac_address(&bssid, if_index);
        if (ret)
            goto error;

        freq = nl_get_frequency(if_index);
        if (freq <= 0)
            goto error;
    }

    {
        of_sdwn_entity_accesspoint_name_set(ap_entity, ap->name ? ap->name : "");
        memcpy(&of_bssid.addr, &bssid, OF_MAC_ADDR_BYTES);
        of_sdwn_entity_accesspoint_bssid_set(ap_entity, of_bssid);
        memcpy(&of_phy_mac.addr, &wdev->mac, OF_MAC_ADDR_BYTES);
        of_sdwn_entity_accesspoint_phy_mac_set(ap_entity, of_phy_mac);
        of_ssid.data = (uint8_t*) ap->ssid;
        of_ssid.bytes = strlen(ap->ssid);
        of_sdwn_entity_accesspoint_ssid_set(ap_entity, &of_ssid);

        if (!wdev->disabled && wdev->up)
            ap_config |= OFP_AP_ENABLED;
        of_sdwn_entity_accesspoint_config_set(ap_entity, ap_config);

        of_sdwn_entity_accesspoint_if_no_set(ap_entity,
                (of_port_no_t) if_index);


        of_sdwn_entity_accesspoint_curr_freq_set(ap_entity, freq);
    }

    return ap_entity;

out_of_mem:
    fprintf(stderr, "Failed to allocate access point objects\n");
    return NULL;

error:
    fprintf(stderr, "Failed to extract AP info\n");
    return NULL;
}

static int
wdev_info_to_of(struct wdev_info *info, size_t n_wdev,
    of_list_sdwn_entity_t *list, of_version_t version)
{
    struct wdev_info *cur_wdev;
    struct ap_info *cur_ap;
    
    struct wphy_info *wphy;

    of_sdwn_entity_nic_t *nic;
    of_sdwn_entity_accesspoint_t *ap;
    int ret;

    cur_wdev = info;
    for (size_t i = 0; i++ < n_wdev; cur_wdev++) {
        
        if (!cur_wdev->up || cur_wdev->disabled)
            continue;

        // NIC info
        ret = add_nic(list, cur_wdev, version);
        if (ret)
            goto error;

        if (!cur_wdev->aps)
            continue;

        cur_ap = cur_wdev->aps;
        for (size_t j = 0; j++ < cur_wdev->n_aps; cur_ap++) {
            
            ap = ap_info_to_of(cur_wdev, cur_ap, version);
            if (!ap)
                goto error;

            of_list_sdwn_entity_append(list, ap);
        }
    }

    return 0;

error:
    return -1;
}

/* Make a ubus call to 'network.wireless' status to collect information about
 * wireless devices, interfaces and access points.
 * Information is converted to loci types and appended to 'list'.
 * Monitoring is started for all found interfaces.
 */
static struct wdev_info*
build_sdwn_entities_list(of_list_sdwn_entity_t *list, of_version_t version,
    size_t *n_wdev)
{
    int ret;
    struct wdev_info *wireless_info;
    size_t n;

    if (ubus_get_wireless_info(&wireless_info, &n))
        goto error;

    ret = wdev_info_to_of(wireless_info, n, list, version);
    if (ret)
        goto error;

    *n_wdev = n;
    return wireless_info;

error:
    *n_wdev = 0;
    free(wireless_info);
    return NULL;
}

static int
discover_related_of_switches(of_list_sdwn_entity_t *list, of_version_t version)
{
    char **rel_switches;
    int ret;
    of_sdwn_entity_related_switch_t *rel_sw;
    uint64_t dpid;
    size_t n_sw;

    ret = sysfs_lookup_ovs_bridges(&rel_switches, &n_sw);
    if (ret) {
        fprintf(stderr, "Failed to look up relative ovs switches\n");
        return -1;
    }

    for (size_t i = 0; i < n_sw; i++) {
        ret = ubus_get_ovs_datapath_id(rel_switches[i], &dpid);
        if (ret)
            continue;

        rel_sw = of_sdwn_entity_related_switch_new(version);
        if (!rel_sw)
            break;

        of_sdwn_entity_related_switch_datapath_id_set(rel_sw, dpid);
        of_list_sdwn_entity_append(list, rel_sw);
    }

    for (size_t i = 0; i < n_sw; i++)
        free(rel_switches[i]);
    free(rel_switches);

    return 0;
}

/* SDWN driver sub-handshake messages */

int
conn_handle_experimenter_port_desc_multipart_request(indigo_cxn_id_t cxn_id,
    of_exp_port_desc_request_t *req, pthread_mutex_t *mutex)
{
    uint32_t xid;
    of_exp_port_desc_reply_t *reply;
    of_list_sdwn_entity_t *entities;
    struct wdev_info *wireless_info;
    int ret;
    size_t n_if, n_wdev;

    reply = of_exp_port_desc_reply_new(req->version);
    if (!reply) {
        printf("Failed to allocate response object\n");
        return -1;
    }

    entities = of_list_sdwn_entity_new(req->version);
    if (!entities) {
        printf("Failed to allocate entities list object\n");
        return -1;
    }

    wireless_info = build_sdwn_entities_list(entities, req->version, &n_wdev);
    if (!wireless_info) {
        printf("Error building SDWN entities list\n");
        return -1;
    }

    of_exp_port_desc_request_xid_get(req, &xid);
    of_exp_port_desc_reply_xid_set(reply, xid);

    indigo_cxn_send_controller_message(cxn_id, reply);

    printf("Experimenter Port Description reply sent\n");

    // start monitoring
    char *interfaces[wireless_info->n_aps];
    for (size_t i = 0; i < wireless_info->n_aps; i++)
        interfaces[i] = wireless_info->aps[i].name;

    mon_init(interfaces, wireless_info->n_aps, mutex, cxn_id);

    for (size_t i = 0; i < n_wdev; i++) {
        for (size_t j = 0; j < wireless_info[i].n_aps; j++) {
            free(wireless_info[i].aps[j].name);
            free(&wireless_info[i].aps[j]);
            free(wireless_info[i].name);
        }
    }

    free(wireless_info);

    return 0;
}

int
conn_handle_sdwn_port_desc_multipart_request(indigo_cxn_id_t cxn_id,
    of_exp_port_desc_request_t *req, pthread_mutex_t *mutex)
{
    uint32_t xid;
    of_exp_port_desc_reply_t *reply;
    of_list_sdwn_entity_t *entities;
    struct wdev_info *wireless_info;
    int ret;
    size_t n_if, n_wdev;
    struct wdev_info *cur_wdev;
    struct ap_info *cur_ap;

    reply = of_sdwn_port_desc_reply_new(req->version);
    if (!reply) {
        printf("Failed to allocate response object\n");
        return -1;
    }

    entities = of_list_sdwn_entity_new(req->version);
    if (!entities) {
        printf("Failed to allocate entities list object\n");
        return -1;
    }

    wireless_info = build_sdwn_entities_list(entities, req->version, &n_wdev);
    if (!wireless_info) {
        printf("Error building SDWN entities list\n");
        return -1;
    }

    ret = discover_related_of_switches(entities, req->version);
    if (ret) {
        fprintf(stderr, "Failed to get related OF switches\n");
    }

    of_sdwn_port_desc_request_xid_get(req, &xid);
    of_sdwn_port_desc_reply_xid_set(reply, xid);
    of_sdwn_port_desc_reply_entities_set(reply, entities);

    _DEBUG_print_sdwn_entities(entities);

    indigo_cxn_send_controller_message(cxn_id, reply);

    printf("SDWN Port Description reply sent\n");

    cur_wdev = wireless_info;
    for (size_t j = 0; j < n_wdev; cur_wdev++, j++) {
        if (!cur_wdev->disabled) {
            cur_ap = cur_wdev->aps;
            for (size_t i = 0; i < cur_wdev->n_aps; cur_ap++, i++) {
                if (!cur_ap->name)
                    continue;

                ubus_mon_init(cur_ap->name, cur_ap->ifindex, &cur_ap->bssid,
                              cur_wdev->channel, cxn_id, req->version,
                              cur_ap->encrypted);
            }
        }
    }

    cur_wdev = wireless_info;
    for (size_t i = 0; i++ < n_wdev; cur_wdev++) {
        cur_ap = cur_wdev->aps;
        for (size_t j = 0; j++ < cur_wdev->n_aps; cur_ap++)
            free(cur_ap->name);

        free(cur_wdev->name);
        free(cur_wdev->aps);
    }

    free(wireless_info);
    return 0;
}

int
conn_send_ieee80211_mgmt(indigo_cxn_id_t cxn_id, of_version_t of_version,
                         const char *mgmt_type, char *src_mac, char *dst_mac,
                         uint32_t ssi, uint32_t freq, uint32_t port_no,
                         uint32_t *xid_dst)
{
    of_sdwn_ieee80211_mgmt_t *frame;
    of_mac_addr_t s_mac, d_mac;
    uint8_t type;
    uint32_t xid = conn_next_xid();

    if (!strcmp(mgmt_type, "mgmt")) {
        type = 0x00;
    } else if (!strcmp(mgmt_type, "probe")) {
        type = 0x01;
    } else if (!strcmp(mgmt_type, "assoc")) {
        type = 0x02;
    } else if (!strcmp(mgmt_type, "auth")) {
        type = 0x03;
    } else {
        return -1;
    }

    frame = of_sdwn_ieee80211_mgmt_new(of_version);
    if (!frame)
        goto error;

    of_sdwn_ieee80211_mgmt_xid_set(frame, xid);
    of_sdwn_ieee80211_mgmt_ieee80211_type_set(frame, type);
    of_sdwn_ieee80211_mgmt_addr_set(frame,
        *(of_mac_addr_t*) ether_aton(src_mac));
    of_sdwn_ieee80211_mgmt_target_set(frame,
        *(of_mac_addr_t*) ether_aton(dst_mac));
    of_sdwn_ieee80211_mgmt_ssi_set(frame, ssi);
    of_sdwn_ieee80211_mgmt_freq_set(frame, freq);
    of_sdwn_ieee80211_mgmt_if_no_set(frame, port_no);

    indigo_cxn_send_controller_message(cxn_id, frame);

    // printf("IEEE 802.11 Management Frame Message sent\n");

    *xid_dst = xid;
    return 0;

error:
    fprintf(stderr, "Failed to notify controller about %s frame\n", mgmt_type);
    return -1;
}

int
conn_send_add_client(indigo_cxn_id_t cxn_id, of_version_t of_version,
                     uint32_t assoc_id, struct ether_addr *client_mac,
                     uint32_t if_no, uint16_t caps,
                     char *supported_rates, struct ieee80211_ht_cap *ht_caps)
{
    of_ieee80211_ht_cap_t *of_ht_cap;
    uint16_t cap_flags = 0;

    of_sdwn_add_client_t *msg = of_sdwn_add_client_new(of_version);

    of_sdwn_add_client_ap_set(msg, if_no);
    of_sdwn_add_client_client_set(msg, *(of_mac_addr_t*) client_mac);
    of_sdwn_add_client_assoc_id_set(msg, assoc_id);

    if (supported_rates)
        of_sdwn_add_client_supported_rates_set(msg, supported_rates);

    if (ht_caps && (of_ht_cap = ieee_ht_caps_to_of(ht_caps, of_version))) {
        cap_flags |= IEEE80211_CAPABILITY_FLAG_HT_CAP;
        of_sdwn_add_client_ht_capabilities_set(msg, of_ht_cap);
    }

    of_sdwn_add_client_capabilities_set(msg, caps);
    of_sdwn_add_client_xid_set(msg, conn_next_xid());

    // pthread_mutex_lock (&mutex);
    indigo_cxn_send_controller_message(cxn_id, msg);
    // pthread_mutex_unlock (&mutex);
    return 0;
}

int
conn_send_del_client(indigo_cxn_id_t cxn_id, of_version_t of_version,
                     struct ether_addr *client_mac, uint32_t if_no)
{
    of_sdwn_del_client_t *msg = of_sdwn_del_client_new(of_version);
    if (!msg)
        return -1;

    of_sdwn_del_client_ap_set(msg, if_no);
    of_sdwn_del_client_client_set(msg, *(of_mac_addr_t*) client_mac);
    of_sdwn_del_client_xid_set(msg, conn_next_xid());

    indigo_cxn_send_controller_message(cxn_id, msg);
    return 0;
}

int
conn_handle_sdwn_mgmt_reply_cmd(indigo_cxn_id_t cxn_id,
                                 of_sdwn_ieee80211_mgmt_reply_t *cmd)
{
    uint32_t xid;
    bool deny;
    of_port_no_t if_no;

    of_sdwn_ieee80211_mgmt_reply_xid_get(cmd, &xid);
    of_sdwn_ieee80211_mgmt_reply_deny_get(cmd, (uint8_t*) &deny);
    of_sdwn_ieee80211_mgmt_reply_if_no_get(cmd, &if_no);

    ubus_event_respond(if_no, xid, deny);
}

static int
send_get_clients_reply_normal(indigo_cxn_id_t cxn_id, of_version_t of_version,
                           uint32_t xid, struct stainfo *client, bool more)
{
    of_ieee80211_ht_cap_t *of_ht_cap;
    of_sdwn_get_clients_reply_normal_t *reply;

    uint16_t flags = more ? OF_STATS_REPLY_FLAG_REPLY_MORE : 0;
    uint16_t cap_flags = 0;

    reply = of_sdwn_get_clients_reply_normal_new(of_version);
    if (!reply)
        return -1;

    of_sdwn_get_clients_reply_normal_flags_set(reply, flags);
    of_sdwn_get_clients_reply_normal_client_type_set(reply,
                                           OFP_SDWN_GET_CLIENTS_REPLY_TYPE_NORMAL);

    of_sdwn_get_clients_reply_normal_mac_set(reply,
            *(of_mac_addr_t*) &client->mac);

    of_sdwn_get_clients_reply_normal_assoc_id_set(reply, client->assoc_id);
    of_sdwn_get_clients_reply_normal_capabilities_set(reply, client->capabilities);

    if (client->ht_cap &&
        (of_ht_cap = ieee_ht_caps_to_of(client->ht_cap, of_version))) {
            IEEE80211_CAPABILITY_FLAG_HT_CAP_SET(of_version, cap_flags);
            of_sdwn_get_clients_reply_normal_ht_capabilities_set(reply, of_ht_cap);
    }

    of_sdwn_get_clients_reply_normal_cap_flags_set(reply, cap_flags);

    if (client->supported_rates) {
        of_sdwn_get_clients_reply_normal_supported_rates_set(reply,
            client->supported_rates);
    }

    of_sdwn_get_clients_reply_normal_xid_set(reply, xid);

    indigo_cxn_send_controller_message(cxn_id, reply);

    printf("Get Clients reply sent (normal)\n");
    return 0;
}

static int
send_get_clients_reply_crypto(indigo_cxn_id_t cxn_id, of_version_t of_version,
                           uint32_t xid, struct stainfo_crypto *client, bool more)
{
    of_ieee80211_ht_cap_t *of_ht_cap;
    of_sdwn_get_clients_reply_crypto_t *reply =
        of_sdwn_get_clients_reply_crypto_new(of_version);
    
    uint16_t flags = more ? OF_STATS_REPLY_FLAG_REPLY_MORE : 0;
    uint16_t cap_flags = 0;

    if (!reply)
        return -1;

    of_list_bsn_tlv_data_t *keylist = of_list_bsn_tlv_data_new(of_version);
    
    of_bsn_tlv_data_t *pmk = of_bsn_tlv_data_new(of_version);
    of_octets_t of_pmk = {
        .data = client->pmk,
        .bytes = client->pmk_len
    };

    of_bsn_tlv_data_value_set(pmk, &of_pmk);
    of_list_bsn_tlv_data_append(keylist, pmk);

    of_bsn_tlv_data_t *kck = of_bsn_tlv_data_new(of_version);
    of_octets_t of_kck = {
        .data = client->kck,
        .bytes = client->kck_len
    };

    of_bsn_tlv_data_value_set(kck, &of_kck);
    of_list_bsn_tlv_data_append(keylist, kck);

    of_bsn_tlv_data_t *kek = of_bsn_tlv_data_new(of_version);
    of_octets_t of_kek = {
        .data = client->kek,
        .bytes = client->kek_len
    };

    of_bsn_tlv_data_value_set(kek, &of_kek);
    of_list_bsn_tlv_data_append(keylist, kek);

    of_bsn_tlv_data_t *tk = of_bsn_tlv_data_new(of_version);
    of_octets_t of_tk = {
        .data = client->tk,
        .bytes = client->tk_len
    };

    of_bsn_tlv_data_value_set(tk, &of_tk);
    of_list_bsn_tlv_data_append(keylist, tk);

    of_bsn_tlv_data_t *seq = of_bsn_tlv_data_new(of_version);
    of_octets_t of_seq = {
        .data = client->seq,
        .bytes = client->seq_len
    };

    of_bsn_tlv_data_value_set(seq, &of_seq);
    of_list_bsn_tlv_data_append(keylist, seq);

    if (client->client_info.ht_cap && 
        (of_ht_cap = ieee_ht_caps_to_of(client->client_info.ht_cap, of_version))) {
            IEEE80211_CAPABILITY_FLAG_HT_CAP_SET(of_version, cap_flags);
            of_sdwn_get_clients_reply_crypto_ht_capabilities_set(reply, of_ht_cap);
    }

    of_sdwn_get_clients_reply_crypto_flags_set(reply, flags);
    of_sdwn_get_clients_reply_crypto_client_type_set(reply,
                                           OFP_SDWN_GET_CLIENTS_REPLY_TYPE_CRYPTO);

    of_sdwn_get_clients_reply_crypto_mac_set(reply,
            *(of_mac_addr_t*) &client->client_info.mac);

    of_sdwn_get_clients_reply_crypto_assoc_id_set(reply, client->client_info.assoc_id);
    of_sdwn_get_clients_reply_crypto_capabilities_set(reply,
            client->client_info.capabilities);
    of_sdwn_get_clients_reply_crypto_keys_set(reply, keylist);
    of_sdwn_get_clients_reply_crypto_xid_set(reply, xid);

    indigo_cxn_send_controller_message(cxn_id, reply);

    printf("Get Clients reply sent (with crypto params)\n");
    return 0;
}

int
conn_send_get_clients_reply(indigo_cxn_id_t cxn_id, of_version_t of_version,
                         uint32_t xid, union station_info *client, bool encrypted,
                         bool more)
{
    if (encrypted)
        return send_get_clients_reply_crypto(cxn_id, of_version, xid,
                &client->encrypted, more);
    else
        return send_get_clients_reply_normal(cxn_id, of_version, xid,
                &client->client_info, more);
}

