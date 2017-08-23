#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <net/ethernet.h>
#include <pthread.h>

#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/msg.h>
#include <netlink/attr.h>
#define _LINUX_IF_H // I really don't want this file!
#include <netlink/route/link.h>
#include <errno.h>
#include <linux/nl80211.h>
// #include <net/if.h>

#include "nl.h"
#include "utils.h"


struct nl80211_state {
	struct nl_sock *nl_sock;
	int nl80211_id;
};

struct nl80211_state nlstate;

uint8_t channel = 36;
uint8_t ether[ETH_ALEN]={0xD0, 0x0E, 0xA4, 0x81, 0xfc, 0x00};
uint16_t beacon_int = 200;

static int
error_handler(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg)
{
	int *ret = arg;
	*ret = err->error;
	printf("->CFG80211 returns: error %d, %s\n", err->error,
		strerror((-1)*err->error));

	return NL_STOP;
}

static int
finish_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;
	*ret = 0;
	printf("Finish handler called\n");
	return NL_SKIP;
}

static int
ack_handler(struct nl_msg *msg, void *arg)
{
	int *ret = arg;
	*ret = 0;
	return NL_STOP;
}

int
nl_get_mac_address(struct ether_addr *mac, unsigned int if_index) {
	struct nl_sock *nl_sock;
	struct nl_cache *cache;
	struct rtnl_link *link;

	if (!(nl_sock=nl_socket_alloc())) {
		fprintf(stderr, "Failed to allocate netlink socket.\n");
	}

	if (nl_connect(nl_sock, NETLINK_ROUTE)) {
		fprintf(stderr, "Failed to connect to route netlink.\n");
		goto out_socket;
	}

	if (rtnl_link_alloc_cache(nl_sock, AF_UNSPEC, &cache) < 0) {
		printf("critical: did not get cache\n");
		goto out_socket;
	}

	if (!(link = rtnl_link_get(cache, if_index))) {
		printf("critical: did not get device\n");
		goto out_cache;
	}

	struct nl_addr* addr = rtnl_link_get_addr(link);
	memcpy(mac, nl_addr_get_binary_addr(addr), ETH_ALEN);
	rtnl_link_put(link);

	return 0;
out_cache:
	nl_cache_put(cache);

out_socket:
	nl_socket_free(nl_sock); //closes as well
	return -1;
}

static int
handle_del_station(struct nlattr **tb) {

	printf("call :: %s\n", __func__);

	struct ether_addr mac, bssid;
	char if_name[IF_NAMESIZE + 1];
	memset(if_name, 0, IF_NAMESIZE + 1);

	if (!tb[NL80211_ATTR_MAC]) {
		fprintf(stderr, "expected NL80211_ATTR_MAC\n");
		goto skip;
	}

	if (!tb[NL80211_ATTR_IFINDEX]) {
		fprintf(stderr, "expected NL80211_ATTR_IFINDEX\n");
		goto skip;
	}

	nl_get_mac_address(&bssid, nla_get_u32(tb[NL80211_ATTR_IFINDEX]));
	if_indextoname(nla_get_u32(tb[NL80211_ATTR_IFINDEX]), if_name);
	memcpy(&mac, nla_data(tb[NL80211_ATTR_MAC]), ETH_ALEN);

	wf_del_client(nla_get_u32(tb[NL80211_ATTR_IFINDEX]), &mac, if_name);

skip:
	return NL_SKIP;
}

static int
nl80211_init(struct nl80211_state *state)
{
	int err;

	state->nl_sock = nl_socket_alloc();
	if (!state->nl_sock) {
		fprintf(stderr, "Failed to allocate netlink socket.\n");
		return -ENOMEM;
	}

	nl_socket_set_buffer_size(state->nl_sock, 8192, 8192);

	if (genl_connect(state->nl_sock)) {
		fprintf(stderr, "Failed to connect to generic netlink.\n");
		err = -ENOLINK;
		goto out_handle_destroy;
	}

	state->nl80211_id = genl_ctrl_resolve(state->nl_sock, "nl80211");
	if (state->nl80211_id < 0) {
		fprintf(stderr, "nl80211 not found.\n");
		err = -ENOENT;
		goto out_handle_destroy;
	}

	return 0;

out_handle_destroy:
	nl_socket_free(state->nl_sock);
	return err;
}

static int
error_handler_test(struct sockaddr_nl *nla, struct nlmsgerr *err, void *arg)
{
	int *ret = arg;
	*ret = err->error;
	printf("!!!ERROR TEST HANDLER called: err->error:%d\n",err->error);
	return NL_STOP;
}

struct get_if_index_cb_args {
	const char *phy_name; 
    struct ether_addr* mac;
    unsigned int if_index;
};

static int
mac_to_if_index_cb(struct nl_msg *msg, struct get_if_index_cb_args *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (!tb[NL80211_ATTR_MAC] ||
		memcmp(nla_data(tb[NL80211_ATTR_MAC]), arg->mac, ETH_ALEN))
		return NL_SKIP;

	if (!tb[NL80211_ATTR_IFINDEX])
		return NL_STOP;

	arg->if_index = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);
	return NL_STOP;
}

static int
wiphyname_to_if_index_cb(struct nl_msg *msg, struct get_if_index_cb_args *arg)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (tb[NL80211_ATTR_WIPHY_NAME])
		printf("Got phy name '%s'\n", (char*) nla_data(tb[NL80211_ATTR_WIPHY_NAME]));

	if (!tb[NL80211_ATTR_WIPHY_NAME] || 
		strcmp((char*) nla_data(tb[NL80211_ATTR_WIPHY_NAME]), arg->phy_name))
		return NL_SKIP;

	if (!tb[NL80211_ATTR_IFINDEX])
		return NL_SKIP;

	arg->if_index = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);

	printf("got if_index %d\n", nla_get_u32(tb[NL80211_ATTR_IFINDEX]));

	return NL_STOP;
}

static unsigned int
mac_to_if_index(struct ether_addr *mac)
{
	struct nl_msg *msg;
	struct nl_cb *cb = NULL;

	int ret = -1;
	int err;
	int finished = 0;

	struct get_if_index_cb_args args = {NULL, mac, 0};

	msg = nlmsg_alloc();
	if (!msg)
		goto out;

	genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0, NLM_F_DUMP,
		NL80211_CMD_GET_INTERFACE, 0);

	cb = nl_cb_alloc(NL_CB_CUSTOM);
	if (!cb)
		goto out;

	if (nl_send_auto_complete(nlstate.nl_sock, msg) < 0)
		goto out;

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM,
			  (nl_recvmsg_msg_cb_t) mac_to_if_index_cb, &args);

	err = nl_recvmsgs(nlstate.nl_sock, cb);

	if (err < 0)
		goto out;

	ret = 0;
	return args.if_index;

 out:
	nl_cb_put(cb);
	nlmsg_free(msg);
	printf("NLA_PUT_FAILURE in mac_to_if_index\n");
	return 0;
}

static unsigned int
wiphyname_to_if_index(const char *wiphyname)
{
	struct nl_msg *msg;
	struct nl_cb *cb = NULL;

	int ret = -1;
	int err;
	int finished = 0;

	struct get_if_index_cb_args args = {wiphyname, NULL, 0};

	msg = nlmsg_alloc();
	if (!msg)
		goto out;

	genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0, NLM_F_DUMP,
		NL80211_CMD_GET_WIPHY, 0);

	cb = nl_cb_alloc(NL_CB_CUSTOM);
	if (!cb)
		goto out;

	if (nl_send_auto_complete(nlstate.nl_sock, msg) < 0)
		goto out;

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM,
		(nl_recvmsg_msg_cb_t) wiphyname_to_if_index_cb, &args);
	//nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, wait_handler, &finished);

	err = nl_recvmsgs(nlstate.nl_sock, cb);

	if (err < 0)
		goto out;

	ret = 0;
	return args.if_index;

 out:
	nl_cb_put(cb);
	nlmsg_free(msg);
	printf("NLA_PUT_FAILURE in mac_to_if_index\n");
	return 0;
}

struct get_wphy_info_cb_args { 
	struct wphy_info *phy;

	/* for internal use to maintain state across multiple calls to the callback
	 */
	int64_t cur_phy_id;
	int last_band;
	bool band_had_freq;

	struct info_buf band_buf;
	struct info_buf freq_buf;
	struct info_buf rate_buf;

	struct ieee80211_band cur_band;
	struct ieee80211_freq_info cur_freq;
};

static int
get_wphy_info_cb(struct nl_msg *msg, struct get_wphy_info_cb_args *args)
{
	struct nlattr *tb_msg[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

	struct nlattr *tb_band[NL80211_BAND_ATTR_MAX + 1];

	struct nlattr *tb_freq[NL80211_FREQUENCY_ATTR_MAX + 1];
	static struct nla_policy freq_policy[NL80211_FREQUENCY_ATTR_MAX + 1] = {
		[NL80211_FREQUENCY_ATTR_FREQ] = { .type = NLA_U32 },
		[NL80211_FREQUENCY_ATTR_DISABLED] = { .type = NLA_FLAG },
		[NL80211_FREQUENCY_ATTR_NO_IR] = { .type = NLA_FLAG },
		[__NL80211_FREQUENCY_ATTR_NO_IBSS] = { .type = NLA_FLAG },
		[NL80211_FREQUENCY_ATTR_RADAR] = { .type = NLA_FLAG },
		[NL80211_FREQUENCY_ATTR_MAX_TX_POWER] = { .type = NLA_U32 },
	};

	struct nlattr *tb_rate[NL80211_BITRATE_ATTR_MAX + 1];
	static struct nla_policy rate_policy[NL80211_BITRATE_ATTR_MAX + 1] = {
		[NL80211_BITRATE_ATTR_RATE] = { .type = NLA_U32 },
		[NL80211_BITRATE_ATTR_2GHZ_SHORTPREAMBLE] = { .type = NLA_FLAG },
	};

	struct nlattr *nl_band;
	struct nlattr *nl_freq;
	struct nlattr *nl_rate;
	struct nlattr *nl_mode;
	struct nlattr *nl_cmd;
	struct nlattr *nl_if, *nl_ftype;
	int rem_band, rem_freq, rem_rate, rem_mode, rem_cmd, rem_ftype, rem_if;

	nla_parse(tb_msg, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	if (tb_msg[NL80211_ATTR_WIPHY])
		args->cur_phy_id = nla_get_u32(tb_msg[NL80211_ATTR_WIPHY]);

	uint32_t cur_rate;

	if (!tb_msg[NL80211_ATTR_WIPHY_NAME])
		return NL_SKIP;

	char *phy_name;

	phy_name = nla_get_string(tb_msg[NL80211_ATTR_WIPHY_NAME]);
	args->phy->name = malloc(strlen(phy_name + 1));
	if (!args->phy->name)
		return -ENOMEM;

	strcpy(args->phy->name, phy_name);

	if (!tb_msg[NL80211_ATTR_WIPHY_BANDS])
		return 0;

	nla_for_each_nested(nl_band, tb_msg[NL80211_ATTR_WIPHY_BANDS], rem_band) {

		// Parsing new band. Add previously gathered info to buffer
		if (nl_band->nla_type != args->last_band) {
			args->band_had_freq = false;

			// unless this is the first band parsed, add band info to buffer
			if (args->last_band != -1) {

				// add gathered frequency info and reset freq_buf
				args->cur_band.freqs = (struct ieee80211_freq_info*) args->freq_buf.buf;
				args->cur_band.n_freqs = args->freq_buf.n_el;
				info_buf_reset(&args->freq_buf);

				// add gathered rates info and reset rate_buf
				args->cur_band.rates = (uint32_t*) args->rate_buf.buf;
				args->cur_band.n_rates = args->rate_buf.n_el;
				info_buf_reset(&args->rate_buf);

				info_buf_append(&args->band_buf, &args->cur_band);
			}

			// clear cur_band struct
			memset(&args->cur_band, 0, sizeof(struct ieee80211_band));
		}

		args->last_band = nl_band->nla_type;

		nla_parse(tb_band, NL80211_BAND_ATTR_MAX, nla_data(nl_band),
			  nla_len(nl_band), NULL);

		if (tb_band[NL80211_BAND_ATTR_HT_CAPA]) {
			if (!args->cur_band.ht_cap) {
				args->cur_band.ht_cap = malloc(sizeof(struct ieee80211_ht_cap));
				if (!args->cur_band.ht_cap)
					return -ENOMEM;
			}
			args->cur_band.ht_cap->cap_info = 
				nla_get_u16(tb_band[NL80211_BAND_ATTR_HT_CAPA]);
		}

		if (tb_band[NL80211_BAND_ATTR_HT_AMPDU_FACTOR]) {
			if (!args->cur_band.ht_cap) {
				args->cur_band.ht_cap = malloc(sizeof(struct ieee80211_ht_cap));
				if (!args->cur_band.ht_cap)
					return -ENOMEM;
			}
			args->cur_band.ht_cap->ampdu_params_info |= 
				nla_get_u8(tb_band[NL80211_BAND_ATTR_HT_AMPDU_FACTOR]);
		}

		if (tb_band[NL80211_BAND_ATTR_HT_AMPDU_DENSITY]) {
			if (!args->cur_band.ht_cap) {
				args->cur_band.ht_cap = malloc(sizeof(struct ieee80211_ht_cap));
				if (!args->cur_band.ht_cap)
					return -ENOMEM;
			}
			args->cur_band.ht_cap->ampdu_params_info |= 
				(nla_get_u8(tb_band[NL80211_BAND_ATTR_HT_AMPDU_DENSITY]) << 2);
		}

		if (tb_band[NL80211_BAND_ATTR_HT_MCS_SET] &&
		    nla_len(tb_band[NL80211_BAND_ATTR_HT_MCS_SET]) == 16) {
				if (!args->cur_band.ht_cap) {
					args->cur_band.ht_cap = malloc(sizeof(struct ieee80211_ht_cap));
					if (!args->cur_band.ht_cap)
						return -ENOMEM;
				}
				memcpy(&args->cur_band.ht_cap->mcs,
					nla_data(tb_band[NL80211_BAND_ATTR_HT_MCS_SET]), 16);
		}

		if (tb_band[NL80211_BAND_ATTR_VHT_CAPA] && tb_band[NL80211_BAND_ATTR_VHT_MCS_SET]) {
			if (!args->cur_band.vht_cap) {
				args->cur_band.vht_cap = malloc(sizeof(struct ieee80211_vht_cap));
				if (!args->cur_band.vht_cap)
					return -ENOMEM;
			}		
			args->cur_band.vht_cap->cap_info = 
				nla_get_u32(tb_band[NL80211_BAND_ATTR_VHT_CAPA]),
					nla_data(tb_band[NL80211_BAND_ATTR_VHT_MCS_SET]);
		}

		if (tb_band[NL80211_BAND_ATTR_FREQS]) {

			// If this is the band's first frequency, clear cur_freq struct
			if (!args->band_had_freq) {
				args->band_had_freq = true;
				memset(&args->cur_freq, 0, sizeof(struct ieee80211_freq_info));
			}

			nla_for_each_nested(nl_freq, tb_band[NL80211_BAND_ATTR_FREQS], rem_freq) {
				nla_parse(tb_freq, NL80211_FREQUENCY_ATTR_MAX, nla_data(nl_freq),
					  nla_len(nl_freq), freq_policy);

				if (!tb_freq[NL80211_FREQUENCY_ATTR_FREQ])
					continue;
				
				args->cur_freq.freq = nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_FREQ]);

				if (tb_freq[NL80211_FREQUENCY_ATTR_MAX_TX_POWER] &&
				    !tb_freq[NL80211_FREQUENCY_ATTR_DISABLED])
						args->cur_freq.max_tx_power = nla_get_u32(tb_freq[NL80211_FREQUENCY_ATTR_MAX_TX_POWER]);

				if (tb_freq[NL80211_FREQUENCY_ATTR_DISABLED])
					args->cur_freq.disabled = true;

				// append freq to buffer
				info_buf_append(&args->freq_buf, &args->cur_freq);
			}
		}

		if (tb_band[NL80211_BAND_ATTR_RATES]) {
			nla_for_each_nested(nl_rate, tb_band[NL80211_BAND_ATTR_RATES], rem_rate) {
				
				nla_parse(tb_rate, NL80211_BITRATE_ATTR_MAX, nla_data(nl_rate),
					  nla_len(nl_rate), rate_policy);
				
				if (!tb_rate[NL80211_BITRATE_ATTR_RATE])
					continue;

				cur_rate = nla_get_u32(tb_rate[NL80211_BITRATE_ATTR_RATE]);

				info_buf_append(&args->rate_buf, &cur_rate);
			}
		}
	}

	// append last band
	info_buf_append(&args->band_buf, &args->cur_band);

	args->phy->bands = (struct ieee80211_band*) args->band_buf.buf;
	args->phy->n_bands = args->band_buf.n_el;

	return NL_SKIP;
}

/*
 * TODOs
 *   - DRY! this function looks almost like nl_get_phy_capabilities
 */
int
nl_get_phy_info(struct wphy_info *phy, unsigned int devindex)
{
	struct nl_sock *nl_sock;
	struct nl_msg *msg;
	struct nl_cb *cb, *sock_cb;

	int ret;

	if (!(nl_sock = nl_socket_alloc())) {
		fprintf(stderr, "Failed to allocate netlink socket.\n");
	}

	if (nl_connect(nl_sock, NETLINK_ROUTE)) {
		fprintf(stderr, "Failed to connect to route netlink.\n");
		ret = -1;
		goto nla_put_failure;
	}

	if (!(msg = nlmsg_alloc())) {
		fprintf(stderr, "Failed to allocate netlink message\n");
		ret = -1;
		goto nla_put_failure;
	}

	cb = nl_cb_alloc(NL_CB_DEFAULT);
	sock_cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (!cb || !sock_cb) {
		fprintf(stderr, "Failed to allocate netlink callbacks\n");
		ret = -1;
		goto out_msg;
	}

	genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0, 0, NL80211_CMD_GET_WIPHY, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY, devindex);

	nl_socket_set_cb(nl_sock, sock_cb);
	if ((ret = nl_send_auto_complete(nlstate.nl_sock, msg)) , 0) {
		fprintf(stderr, "nl_send_auto_complete failed\n");
		ret = -1;
		goto out_msg;
	}

	ret = 1;

	struct get_wphy_info_cb_args cb_args = {
		.phy = phy,

		.cur_phy_id = -1,
		.last_band = -1,
		.band_had_freq = false,

		.band_buf = INFO_BUF_INIT(struct ieee80211_band),
		.freq_buf = INFO_BUF_INIT(struct ieee80211_freq_info),
		.rate_buf = INFO_BUF_INIT(uint32_t),
	};

	nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &ret);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &ret);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &ret);
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM,
		      (nl_recvmsg_msg_cb_t) get_wphy_info_cb, &cb_args);

	while (ret > 0)
		nl_recvmsgs(nlstate.nl_sock, cb);

	nl_cb_put(cb);
	nl_cb_put(sock_cb);

out_msg:
	nlmsg_free(msg);

nla_put_failure:
	nl_socket_free(nl_sock); //closes as well

	return ret;
}

void
nl_add_client(struct ether_addr* ap_mac, struct ether_addr* sta_mac,
	uint16_t capability, uint16_t aid, uint8_t *supp_rates,
	size_t supp_rates_len, struct ieee80211_ht_cap *ht_cap,
	struct ieee80211_vht_cap *vht_cap)
{
	printf("call :: %s (AP=%s ", __func__, ether_ntoa(ap_mac));
	printf("STA=%s)\n", ether_ntoa(sta_mac));

	struct nl_msg *msg;
	struct nl_cb *cb_newsta;
	int err_newsta = -ENOMEM;
	unsigned int if_index;
	if_index = mac_to_if_index(ap_mac);
	short listen_interval = 2000;
	msg = nlmsg_alloc();

	genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0, 0, NL80211_CMD_NEW_STATION, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, if_index);
	NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, sta_mac);
	NLA_PUT(msg, NL80211_ATTR_STA_SUPPORTED_RATES, supp_rates_len, supp_rates);

	NLA_PUT_U16(msg, NL80211_ATTR_STA_CAPABILITY, capability);
	if (ht_cap)
		NLA_PUT(msg, NL80211_ATTR_HT_CAPABILITY, NL80211_HT_CAPABILITY_LEN, ht_cap);
	// TODO:
	if (vht_cap)
		NLA_PUT(msg, NL80211_ATTR_VHT_CAPABILITY, NL80211_VHT_CAPABILITY_LEN, vht_cap);

	/*For the 1 AID value here, a valid number 
	 * had to be assigned for each new station*/
	NLA_PUT_U16(msg, NL80211_ATTR_STA_AID, aid);
	NLA_PUT_U16(msg, NL80211_ATTR_STA_LISTEN_INTERVAL, listen_interval);
	{
		struct nl80211_sta_flag_update upd;
		memset(&upd, 0, sizeof(upd));
		upd.set=1<<NL80211_STA_FLAG_WME;
		upd.mask = upd.set;
		NLA_PUT(msg, NL80211_ATTR_STA_FLAGS2, sizeof(upd), &upd);
	}
	/*NLA_PUT_U16(msg, NL80211_ATTR_STA_CAPABILITY, 
	* mgmt->u.assoc_req.capab_info); */	
	cb_newsta = nl_cb_alloc(NL_CB_DEFAULT);
	err_newsta = nl_send_auto_complete(nlstate.nl_sock, msg);
	nl_cb_err(cb_newsta, NL_CB_CUSTOM, error_handler_test, &err_newsta);
	nl_cb_set(cb_newsta, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err_newsta);
	nl_cb_set(cb_newsta, NL_CB_ACK   , NL_CB_CUSTOM, ack_handler, &err_newsta);

	err_newsta = 1;

	while (err_newsta > 0) {
		int res = nl_recvmsgs(nlstate.nl_sock, cb_newsta);
		printf("new sta add, err:%d\n",err_newsta);
	}
	nl_cb_put(cb_newsta);
	nlmsg_free(msg);
	return;
nla_put_failure:
	printf("NLA_PUT_FAILURE\n");
}

void
nl_del_client(struct ether_addr* ap_mac, struct ether_addr* sta_mac)
{
	printf("Trying to remove station %s in driver...\n", ether_ntoa(sta_mac));

	struct nl_msg *msg;
	struct nl_cb *cb_delsta;
	int err_delsta = -ENOMEM;
	unsigned int if_index;
	if_index = mac_to_if_index(ap_mac);
	short listen_interval = 2000;
	msg = nlmsg_alloc();
	genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0, 0, NL80211_CMD_DEL_STATION, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, if_index);
	NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, sta_mac);

	cb_delsta = nl_cb_alloc(NL_CB_DEFAULT);
	err_delsta = nl_send_auto_complete(nlstate.nl_sock, msg);
	nl_cb_err(cb_delsta, NL_CB_CUSTOM, error_handler_test, &err_delsta);
	nl_cb_set(cb_delsta, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err_delsta);
	nl_cb_set(cb_delsta, NL_CB_ACK   , NL_CB_CUSTOM, ack_handler, &err_delsta);

	err_delsta=1;

	while (err_delsta > 0) {
		int res = nl_recvmsgs(nlstate.nl_sock, cb_delsta);
		printf("sta del, err:%d\n",err_delsta);
	}
	nl_cb_put(cb_delsta);
	nlmsg_free(msg);
	return;
nla_put_failure:
	printf("NLA_PUT_FAILURE\n");
}

static int
add_interface(struct ether_addr* bssid)
{
	printf("call :: %s (BSSID=%s)\n", __func__, ether_ntoa(bssid));

	struct nl_msg *msg;
	struct nl_cb *cb_newsta;
	int err_newsta = -ENOMEM;
	short listen_interval = 2000;
	msg = nlmsg_alloc();
	genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0, 0, NL80211_CMD_NEW_INTERFACE, 0);  // still needs %NL80211_ATTR_WIPHY,

	// TODO! remove hard-coded 'phy0'
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY, if_nametoindex("phy0"));
	NLA_PUT_U32(msg, NL80211_ATTR_IFTYPE, NL80211_IFTYPE_AP);
	NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, bssid);
	NLA_PUT_STRING(msg, NL80211_ATTR_IFNAME, "wlanflow%d");

	cb_newsta = nl_cb_alloc(NL_CB_DEFAULT);
	err_newsta = nl_send_auto_complete(nlstate.nl_sock, msg);
	nl_cb_err(cb_newsta, NL_CB_CUSTOM, error_handler_test, &err_newsta);
	nl_cb_set(cb_newsta, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err_newsta);
	nl_cb_set(cb_newsta, NL_CB_ACK   , NL_CB_CUSTOM, ack_handler, &err_newsta);

	err_newsta = 1;

	while (err_newsta > 0) {
		int res = nl_recvmsgs(nlstate.nl_sock, cb_newsta);
		printf("new sta add, err:%d\n", err_newsta);
	}

	nl_cb_put(cb_newsta);
	nlmsg_free(msg);
	return 0;

nla_put_failure:
	fprintf(stderr, "NLA_PUT_FAILURE\n");
	return -1;
}


struct client_cb_args {
    for_all_clients_cb *cb;
    void *params;
};

static int
print_sta_handler(struct nl_msg *msg, struct client_cb_args *arg)
{
	printf("print_sta_handler called\n");

	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *sinfo[NL80211_STA_INFO_MAX + 1];
	struct stainfo_lvap sta;
	char mac_addr[20], state_name[10], dev[20];
	static struct nla_policy stats_policy[NL80211_STA_INFO_MAX + 1] = {
		[NL80211_STA_INFO_INACTIVE_TIME] = { .type = NLA_U32 },
		[NL80211_STA_INFO_RX_BYTES] = { .type = NLA_U32 },
		[NL80211_STA_INFO_TX_BYTES] = { .type = NLA_U32 },
		[NL80211_STA_INFO_LLID] = { .type = NLA_U16 },
		[NL80211_STA_INFO_PLID] = { .type = NLA_U16 },
		[NL80211_STA_INFO_PLINK_STATE] = { .type = NLA_U8 },
	};

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);

	/*
	 * TODO: validate the interface and mac address!
	 * Otherwise, there's a race condition as soon as
	 * the kernel starts sending station notifications.
	 */

	if (!tb[NL80211_ATTR_STA_INFO]) {
		fprintf(stderr, "sta stats missing!");
		return NL_SKIP;
	}
	if (nla_parse_nested(sinfo, NL80211_STA_INFO_MAX,
			     tb[NL80211_ATTR_STA_INFO],
			     stats_policy)) {
		fprintf(stderr, "failed to parse nested attributes!");
		return NL_SKIP;
	}

	memcpy(&sta.mac, nla_data(tb[NL80211_ATTR_MAC]), ETH_ALEN);
	ether_ntoa_r(nla_data(tb[NL80211_ATTR_MAC]), mac_addr);
	if_indextoname(nla_get_u32(tb[NL80211_ATTR_IFINDEX]), dev);
	printf("%s %s", mac_addr, dev);

	if (sinfo[NL80211_STA_INFO_INACTIVE_TIME])
		printf("\t%d",
			nla_get_u32(sinfo[NL80211_STA_INFO_INACTIVE_TIME]));
	if (sinfo[NL80211_STA_INFO_RX_BYTES])
		printf("\t%d",
			nla_get_u32(sinfo[NL80211_STA_INFO_RX_BYTES]));
	if (sinfo[NL80211_STA_INFO_TX_BYTES])
		printf("\t%d",
			nla_get_u32(sinfo[NL80211_STA_INFO_TX_BYTES]));

	printf("\n");
	arg->cb((union station_info*) &sta, true, arg->params);
	return NL_SKIP;
}

void
nl_run_for_all_sta(struct ether_addr* bssid, for_all_clients_cb fn, void* params)
{
	struct nl_msg *msg;
	struct nl_cb *cb = NULL;
	struct client_cb_args cb_args;
	unsigned int if_index;
	if_index = mac_to_if_index(bssid);
	int ret = -1;
	int err;
	int finished = 0;

	msg = nlmsg_alloc();
	if (!msg)
		goto out;

	genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0,
		    NLM_F_DUMP, NL80211_CMD_GET_STATION, 0);

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, if_index);

	cb = nl_cb_alloc(NL_CB_CUSTOM);
	if (!cb)
		goto out;

	if (nl_send_auto_complete(nlstate.nl_sock, msg) < 0)
		goto out;

	cb_args.cb = fn;
	cb_args.params = params;
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM,
		(nl_recvmsg_msg_cb_t) print_sta_handler, &cb_args);
	//nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, wait_handler, &finished);

	err = nl_recvmsgs(nlstate.nl_sock, cb);

	if (err < 0)
		goto out;

	ret = 0;

 out:
	nl_cb_put(cb);
 nla_put_failure:
	nlmsg_free(msg);
	return;
}

static int
get_frequency_cb(struct nl_msg *msg, int *freq)
{
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
	  genlmsg_attrlen(gnlh, 0), NULL);

	if (!tb[NL80211_ATTR_WIPHY_FREQ]) {
		fprintf(stderr, "No frequency\n");
		return NL_SKIP;
	}

	*freq = nla_get_u32(tb[NL80211_ATTR_WIPHY_FREQ]);

	return NL_SKIP;
}

int
nl_get_frequency(uint32_t if_index)
{
	struct nl_msg *msg;
	struct nl_cb *cb;
	int freq;
	int ret;

	msg = nlmsg_alloc();
	cb = nl_cb_alloc(NL_CB_DEFAULT);
	
	genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0, 0, NL80211_CMD_GET_INTERFACE, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, if_index);

	ret = nl_send_auto_complete(nlstate.nl_sock, msg);
	ret = 1;
	nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &ret);
	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM,
			  (nl_recvmsg_msg_cb_t) get_frequency_cb, &freq);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &ret);

	while (ret > 0)
		nl_recvmsgs(nlstate.nl_sock, cb);


	nl_cb_put(cb);
	nlmsg_free(msg);

	return freq;

nla_put_failure:
	printf("NLA_PUT_FAILURE in %s\n", __func__);
	return -ENOBUFS;
}

int
nl_set_channel(unsigned int if_index, int channel)
{
	// TODO
	return 0;
}

int
config_ap(unsigned int if_index, uint8_t* beacon_data, size_t beacon_len)
{
	int err;
	unsigned int freq;
	int dtim_period = 2;
	struct nl_msg *msg;
	struct nl_cb *cb;

	msg = nlmsg_alloc();
	cb = nl_cb_alloc(NL_CB_DEFAULT);
	genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0, 0, NL80211_CMD_SET_WIPHY, 0);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, if_index);
	freq = ieee80211_channel_to_frequency(channel, NL80211_BAND_2GHZ);
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_FREQ, freq);
	/*!!TODO get HTVAL from driver, or check the possibilities*/
	NLA_PUT_U32(msg, NL80211_ATTR_WIPHY_CHANNEL_TYPE, NL80211_CHAN_HT40PLUS);
	/*!TODO find out why iw uses the s_cb and what it is good for*/
	err = nl_send_auto_complete(nlstate.nl_sock, msg);
	err = 1;
	nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);

	while (err > 0) {
		nl_recvmsgs(nlstate.nl_sock, cb);
		if (err != 0) {
			fprintf(stderr, "Could not set channel of device, error:%d\n", err);
			return err;
		}
	}

	nl_cb_put(cb);
	nlmsg_free(msg);

	/*Set beacon parameters and start AP*/
	printf("::Set beacon frame parameters and start AP\n");
	msg = nlmsg_alloc();
	cb = nl_cb_alloc(NL_CB_DEFAULT);
	genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0, 0, 
		NL80211_CMD_START_AP, 0);

	NLA_PUT(msg, NL80211_ATTR_BEACON_HEAD, beacon_len, beacon_data);
	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, if_index);
	NLA_PUT_U32(msg, NL80211_ATTR_BEACON_INTERVAL, beacon_int);
	NLA_PUT_U32(msg, NL80211_ATTR_DTIM_PERIOD, dtim_period);

	err = nl_send_auto_complete(nlstate.nl_sock, msg);
	
	nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
	nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
	nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);
	err = 1;

	while (err > 0) {
		nl_recvmsgs(nlstate.nl_sock, cb);
		if (err != 0) {
			fprintf(stderr, "Beacon Setup and AP Setup failed, error: %d\n", err);
			return err;
		}
	}

	nl_cb_put(cb);
	nlmsg_free(msg);

	return 0;

nla_put_failure:
	printf("NLA_PUT_FAILURE in config_ap\n");
	return -ENOBUFS;
}

int
bringup_interface(unsigned int if_index)
{
	int ret;
	struct nl_sock *nl_sock;
	struct rtnl_link *link, *oldlink;

	if (!(nl_sock=nl_socket_alloc())) {
		fprintf(stderr, "Failed to allocate netlink socket.\n");
		return -1;
	}

	if (nl_connect(nl_sock, NETLINK_ROUTE)) {
		fprintf(stderr, "Failed to connect to route netlink.\n");
		ret = -1;
		goto out_socket;
	}

	link = rtnl_link_alloc();
	if(!link)
		goto out_socket;
	oldlink = rtnl_link_alloc();
	if(!oldlink)
		goto out_newlink;

	rtnl_link_set_ifindex(oldlink, if_index);
	rtnl_link_set_flags(link, IFF_UP);

	rtnl_link_change(nl_sock, oldlink, link, 0);

	rtnl_link_put(oldlink);


out_newlink:
	rtnl_link_put(link);
out_socket:
	nl_socket_free(nl_sock); //closes as well

	return 0;
}

int
nl_add_lvap(struct ether_addr* bssid, uint8_t* beacon_data, size_t beacon_len)
{
	int ret;
	unsigned int if_index;
	if_index = mac_to_if_index(bssid);
	if (if_index) {
		char macaddrbuf[18];
		fprintf(stderr, "trying to add a duplicate BSSID: %s\n",
			ether_ntoa_r(bssid, macaddrbuf));
		return -1;
	}

	ret = add_interface(bssid);
	if (ret)
		return ret;

	if_index = mac_to_if_index(bssid); //should come out of add_interface...
	
	ret = bringup_interface(if_index);
	if (ret)
		return ret;

	return config_ap(if_index, beacon_data, beacon_len);
}

void
nl_del_lvap(struct ether_addr* bssid)
{
	unsigned int if_index;
	if_index = mac_to_if_index(bssid);
	if (! if_index) {
		char macaddrbuf[18];
		printf("trying to remove non-exisitng bssid: %s\n",
			ether_ntoa_r(bssid, macaddrbuf));
		return;
	}

	printf("goind to remove IF\n");

	struct nl_msg *msg;
	struct nl_cb *cb_newsta;
	int err_newsta = -ENOMEM;
	msg = nlmsg_alloc();
	genlmsg_put(msg, 0, 0, nlstate.nl80211_id, 0, 0, NL80211_CMD_DEL_INTERFACE, 0);

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX, if_index);

	cb_newsta = nl_cb_alloc(NL_CB_DEFAULT);
	err_newsta = nl_send_auto_complete(nlstate.nl_sock, msg);
	nl_cb_err(cb_newsta, NL_CB_CUSTOM, error_handler_test, &err_newsta);
	nl_cb_set(cb_newsta, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err_newsta);
	nl_cb_set(cb_newsta, NL_CB_ACK   , NL_CB_CUSTOM, ack_handler, &err_newsta);

	err_newsta=1;

	while (err_newsta > 0) {
		int res = nl_recvmsgs(nlstate.nl_sock, cb_newsta);
		printf("new sta add, err:%d\n",err_newsta);
	}

	nl_cb_put(cb_newsta);
	nlmsg_free(msg);
	printf("IF removed\n");
	return;
nla_put_failure:
	printf("NLA_PUT_FAILURE\n");
}

static int
mlme_handler(struct nl_msg *msg, void *arg)
{
	struct ether_addr mac;
	// struct ether_addr bssid;
	char if_name[IF_NAMESIZE + 1];
	int ret;
	uint32_t if_index;
	struct nlattr *tb[NL80211_ATTR_MAX + 1];
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

	nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0),
		  genlmsg_attrlen(gnlh, 0), NULL);


	if (gnlh->cmd != NL80211_CMD_NEW_STATION) {
		goto skip;
	}

	printf("netlink detected new STA\n");

	if (!tb[NL80211_ATTR_MAC]) {
		printf("expected NL80211_ATTR_MAC\n");
		goto skip;
	}

	if (!tb[NL80211_ATTR_IFINDEX]) {
		printf("expected NL80211_ATTR_IFINDEX\n");
		goto skip;
	}

	if_index = nla_get_u32(tb[NL80211_ATTR_IFINDEX]);

	if (tb[NL80211_ATTR_HT_CAPABILITY]) {
		printf("HT capability!\n");
	}

	if (tb[NL80211_ATTR_VHT_CAPABILITY]) {
		printf("VHT capability!\n");
	}

	// nl_get_mac_address(&bssid, nla_get_u32(tb[NL80211_ATTR_IFINDEX]));
	if_indextoname(if_index, if_name);
	memcpy(&mac, nla_data(tb[NL80211_ATTR_MAC]), ETH_ALEN);

	wf_add_client(if_index, &mac, if_name);

skip:
	if (gnlh->cmd == NL80211_CMD_DEL_STATION) {
		printf("STA disconnected\n");
		handle_del_station(tb);
	}
	return NL_SKIP;
}

void*
mlme_thread(void *arg)
{
	struct nl80211_state nlstate;
	nl80211_init(&nlstate);

	//disable numbers to receive unrequested messages. Sideeffects?
	nl_socket_disable_seq_check(nlstate.nl_sock);

	//our callback function for that
	nl_socket_modify_cb(nlstate.nl_sock, NL_CB_VALID, NL_CB_CUSTOM,
		mlme_handler, NULL);

	int grpid = genl_ctrl_resolve_grp(nlstate.nl_sock, "nl80211",
		NL80211_MULTICAST_GROUP_MLME);
	if (grpid < 0) {
		fprintf(stderr, "group %s not found.\n", NL80211_MULTICAST_GROUP_MLME);
	}

	if (nl_socket_add_memberships(nlstate.nl_sock, grpid, 0) < 0) {
		fprintf(stderr, "could not listen to NL stuff :(\n");
	}

	while (1)
		nl_recvmsgs_default(nlstate.nl_sock);
}

void
mlme_listener_init()
{
	pthread_t p;
	pthread_create (&p, NULL, &mlme_thread, NULL);
}

void
nl_init()
{
	nl80211_init(&nlstate);
	mlme_listener_init();
}
