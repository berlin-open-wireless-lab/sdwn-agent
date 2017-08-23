#include "connection.h"

#include <stdbool.h>
#include <net/if.h>

#include <libubox/utils.h>
#include <libubus.h>

#include "nl.h"
#include "ubus.h"
#include "utils.h"
#include "config.h"
#include "wlanflow.h"

#define UBUS_RECONNECT_TIMEOUT 2

static const char *ubus_path;
static struct ubus_context *ctx;
static struct blob_buf b;
static uint32_t wireless_id, ovsd_id;
LIST_HEAD(mon_list);

struct monitoring_context {
    struct list_head list;
    // FIXME: this should be indigo_cxn_id_t and of_version_t, respectively
    //        but including the indigo headers makes the definitions of 
    //        struct list_head in libubox/list.h and AIM/list.h clash 
    int cxn_id;
    int of_version;

    /* Interface name, index (= OF Port Number), BSSID and channel */
    char name[IF_NAMESIZE + 1];
    uint32_t if_no;
    struct ether_addr bssid;
    uint32_t channel;
    bool encrypted;

    /* ubus subscription data (peer ID, object and wait callback) */
    uint32_t obj_id;
    struct ubus_subscriber subscriber;
    bool subscribed;
    struct ubus_event_handler wait_handler;
    /* list of 802.11 management events (PROBE, AUTH, ASSOC)
     * pending a decision by the controller */
    struct list_head pending_events;
};

typedef void (*event_timeout_cb)(void*);

struct pending_event {
    struct list_head list;
    char type[16];
    uint32_t xid;
    struct ubus_request_data req;
    event_timeout_cb timeout_cb;
};

static struct ubus_method mon_obj_type_methods[] = {};
static struct ubus_object_type mon_obj_type =
    UBUS_OBJECT_TYPE("wlanflow_monitor", mon_obj_type_methods);

/* wlanflow ubus object */
static int
ubus_handle_reload(struct ubus_context *ctx, struct ubus_object *obj,
                   struct ubus_request_data *req, const char *method,
                   struct blob_attr *msg)
{
    if (wlanflow_reload())
        return UBUS_STATUS_UNKNOWN_ERROR;

    return UBUS_STATUS_OK;
}

static struct ubus_method main_obj_methods[] = {
    { .name = "reload", .handler = ubus_handle_reload }
};

static struct ubus_object_type main_obj_type = 
    UBUS_OBJECT_TYPE("wlanflow", main_obj_methods);

static struct ubus_object main_obj = {
    .name = "wlanflow",
    .type = &main_obj_type,
    .methods = main_obj_methods,
    .n_methods = ARRAY_SIZE(main_obj_methods),
};

/* hostapd-related methods */
enum {
    HOSTAPD_FREQUENCY_CODE,
    HOSTAPD_STATIONS,
    __HOSTAPD_MAX,
};

static const struct blobmsg_policy hostapd_return_policy[__HOSTAPD_MAX] = {
    [HOSTAPD_FREQUENCY_CODE] = { .name = "freq", .type = BLOBMSG_TYPE_INT32 },
    [HOSTAPD_STATIONS] = { .name = "clients", .type = BLOBMSG_TYPE_TABLE, },
};

enum {
    CLIENT_AUTH,
    CLIENT_ASSOC,
    CLIENT_AUTHORIZED,
    CLIENT_PREAUTH,
    CLIENT_WDS,
    CLIENT_WMM,
    CLIENT_HT,
    CLIENT_VHT,
    CLIENT_WPS,
    CLIENT_MFP,
    CLIENT_CRYPTO,
    CLIENT_AID,
    CLIENT_PMK,
    CLIENT_KCK,
    CLIENT_KEK,
    CLIENT_TK,
    CLIENT_SEQ,
    CLIENT_CAPAB,
    CLIENT_SUPPORTED_RATES,
    CLIENT_HT_CAPAB,
    CLIENT_VHT_CAPAB,
    __CLIENTS_MAX,
};

static const struct blobmsg_policy client_policy[__CLIENTS_MAX] = {
    [CLIENT_AUTH]      = { .name = "auth", .type = BLOBMSG_TYPE_INT8 },
    [CLIENT_ASSOC]     = { .name = "assoc", .type = BLOBMSG_TYPE_INT8 },
    [CLIENT_AUTHORIZED]= { .name = "authorized", .type = BLOBMSG_TYPE_INT8 },
    [CLIENT_PREAUTH]   = { .name = "preauth", .type = BLOBMSG_TYPE_INT8 },
    [CLIENT_WDS]       = { .name = "wds", .type = BLOBMSG_TYPE_INT8 },
    [CLIENT_WMM]       = { .name = "wmm", .type = BLOBMSG_TYPE_INT8 },
    [CLIENT_HT]        = { .name = "ht", .type = BLOBMSG_TYPE_INT8 },
    [CLIENT_VHT]       = { .name = "vht", .type = BLOBMSG_TYPE_INT8 },
    [CLIENT_WPS]       = { .name = "wps", .type = BLOBMSG_TYPE_INT8 },
    [CLIENT_MFP]       = { .name = "mfp", .type = BLOBMSG_TYPE_INT8 },
    [CLIENT_AID]       = { .name = "aid", .type = BLOBMSG_TYPE_INT32 },
    [CLIENT_CRYPTO]    = { .name = "crypto", .type = BLOBMSG_TYPE_STRING },
    [CLIENT_PMK]       = { .name = "crypto_pmk", .type = BLOBMSG_TYPE_STRING },
    [CLIENT_KCK]       = { .name = "crypto_kck", .type = BLOBMSG_TYPE_STRING },
    [CLIENT_KEK]       = { .name = "crypto_kek", .type = BLOBMSG_TYPE_STRING },
    [CLIENT_TK]        = { .name = "crypto_tk", .type = BLOBMSG_TYPE_STRING },
    [CLIENT_SEQ]       = { .name = "crypto_seq", .type = BLOBMSG_TYPE_STRING },
    [CLIENT_CAPAB]     = { .name = "capability", .type = BLOBMSG_TYPE_INT16 },
    [CLIENT_SUPPORTED_RATES]  = {
        .name = "supported_rates",
        .type = BLOBMSG_TYPE_STRING
    },
    [CLIENT_HT_CAPAB]  = {
        .name = "ht_capabilities",
        .type = BLOBMSG_TYPE_STRING
    },
    [CLIENT_VHT_CAPAB] = {
        .name = "vht_capabilities",
        .type = BLOBMSG_TYPE_STRING
    },
};

struct client_cb_args {
    for_all_clients_cb *cb;
    void *cb_args;
};

static void
get_clients_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    struct client_cb_args *arg = req->priv;
    struct blob_attr *tb[__HOSTAPD_MAX];
    int rc, rem, ret;
    struct blob_attr *cur;
    union station_info client_info_u;
    struct stainfo *client;
    size_t n_clients = 0, cur_client = 0;

    if (blobmsg_parse(hostapd_return_policy, __HOSTAPD_MAX, tb,
        blobmsg_data(msg), blobmsg_len(msg)) != 0)
        return;

    if (!tb[HOSTAPD_FREQUENCY_CODE]) {
        fprintf(stderr, "No frequency received from hostapd\n");
        // goto error;
        return;
    }

    rc = blobmsg_get_u32(tb[HOSTAPD_FREQUENCY_CODE]);

    if (!tb[HOSTAPD_STATIONS]) {
        fprintf(stderr, "No clients found");
        // goto error;
        return;
    }

    // count STAs so we can tell callbacks whether they are the last callback to
    // be called in this run.
    blobmsg_for_each_attr(cur, tb[HOSTAPD_STATIONS], rem)
        n_clients++;

    blobmsg_for_each_attr(cur, tb[HOSTAPD_STATIONS], rem) {
        memset(&client_info_u, 0, sizeof(union station_info));
        client = &client_info_u.client_info;
        const char *macaddr = blobmsg_name(cur);
        
        if (!macaddr) {
            fprintf(stderr, "expected address\n");
            continue;
        } else {
            ether_aton_r(macaddr, &client->mac);
        }

        struct blob_attr *client_tb[__CLIENTS_MAX];
        if (blobmsg_parse(client_policy, __CLIENTS_MAX, client_tb, blobmsg_data(cur),
            blobmsg_len(cur)) != 0) {
            fprintf(stderr, "Failed to parse STA info for %s\n", macaddr);
            continue;
        }

        if(client_tb[CLIENT_AID])
            client->assoc_id = blobmsg_get_u32(client_tb[CLIENT_AID]);

        if(client_tb[CLIENT_CAPAB])
            client->capabilities = blobmsg_get_u16(client_tb[CLIENT_CAPAB]);

        if(client_tb[CLIENT_SUPPORTED_RATES])
            client->supported_rates =
                blobmsg_get_string(client_tb[CLIENT_SUPPORTED_RATES]);

        if(client_tb[CLIENT_HT_CAPAB]) {
            printf("STA has HT capabilities\n");
            if (strlen(blobmsg_get_string(client_tb[CLIENT_HT_CAPAB])) == 
                2 * sizeof(struct ieee80211_ht_cap)) {
                    hexparse(blobmsg_get_string(tb[CLIENT_HT_CAPAB]),
                        (uint8_t*) client->ht_cap);
            }
        }

        if (  (client_tb[CLIENT_PMK] &&
               client_tb[CLIENT_KCK] &&
               client_tb[CLIENT_KEK] &&
               client_tb[CLIENT_TK ] &&
               client_tb[CLIENT_SEQ] )) {

            struct stainfo_crypto *client_c = &client_info_u.encrypted;
        
            char *pmk = blobmsg_get_string(client_tb[CLIENT_PMK]);
            char *kck = blobmsg_get_string(client_tb[CLIENT_KCK]);
            char *kek = blobmsg_get_string(client_tb[CLIENT_KEK]);
            char *tk  = blobmsg_get_string(client_tb[CLIENT_TK ]);
            char *seq = blobmsg_get_string(client_tb[CLIENT_SEQ]);

            client_c->pmk = pmk;
            client_c->pmk_len = strlen(pmk);
            client_c->kck = kck;
            client_c->kck_len = strlen(kck);
            client_c->kek = kek;
            client_c->kek_len = strlen(kek);
            client_c->tk = tk;
            client_c->tk_len = strlen(tk);
            client_c->seq=seq;
            client_c->seq_len = strlen(seq);
        }

        ret = arg->cb(&client_info_u, (++cur_client == n_clients), arg->cb_args);
        if (ret == FOR_ALL_CLIENTS_CB_STATUS_STOP)
            return;
    }
}

int
ubus_run_for_all_clients(uint32_t if_no, for_all_clients_cb fn, void *args)
{
    struct monitoring_context *sub;
    int ret = -1;

    struct client_cb_args cb_args = {
        .cb = fn,
        .cb_args = args,
    };

    list_for_each_entry(sub, &mon_list, list) {

        if (!sub->if_no == if_no)
            continue;

        blob_buf_init(&b, 0);
        ret = ubus_invoke(ctx, sub->obj_id, "get_clients", NULL,
                          get_clients_cb, &cb_args, 3000);
        break;
    }

    return ret;
}

static void
add_string_with_additional_null(struct blob_buf *buf, const char *name,
                                const char *string, size_t strlen)
{
    char *nullbuff = malloc(strlen + 1);
    if (!nullbuff) {
        printf("alloc failed\n");
        return;
    }

    memcpy(nullbuff, string, strlen);
    nullbuff[strlen] = '\0';
    blobmsg_add_string(buf, name, nullbuff);
    free(nullbuff);
}

// TODO: complete CBs to signal successful completion or error to controller.
int
ubus_add_client(uint32_t if_no, union station_info *client, bool encrypted)
{
    struct monitoring_context *cur, *dst = NULL;
    char macaddrstr[20];
    struct stainfo *client_info;
    int ret;

    if (encrypted)
        client_info = &client->encrypted.client_info;
    else
        client_info = &client->client_info;

    ether_ntoa_r(&client_info->mac, macaddrstr);

    list_for_each_entry(cur, &mon_list, list) {
        if (cur->if_no == if_no) {
            dst = cur;
            break;
        }
    }

    if (!dst) {
        fprintf(stderr, "Could not add client to AP %s: not found\n",
                cur->name);
        return -1;
    }

    blob_buf_init(&b, 0);
    blobmsg_add_string(&b, "addr", macaddrstr);

    if (encrypted) {
        struct stainfo_crypto *client_info_c = &client->encrypted;
        add_string_with_additional_null(&b, "crypto_pmk", client_info_c->pmk,
            client_info_c->pmk_len);
        add_string_with_additional_null(&b, "crypto_kck", client_info_c->kck,
            client_info_c->kck_len);
        add_string_with_additional_null(&b, "crypto_kek", client_info_c->kek,
            client_info_c->kek_len);
        add_string_with_additional_null(&b, "crypto_tk" , client_info_c-> tk,
            client_info_c->tk_len);
        add_string_with_additional_null(&b, "crypto_seq", client_info_c->seq,
            client_info_c->seq_len);
    }

    printf("Adding client to AP:\n");
    _DEBUG_print_station_info(client, encrypted);

    ret = ubus_invoke(ctx, dst->obj_id, "add_client", b.head, NULL, NULL,
                      3000);

    if (ret)
        fprintf(stderr, "Failed to add client: %s\n", ubus_strerror(ret));

    return ret;
}

// TODO: complete CBs to signal successfull completion or error to controller.
int
ubus_del_client(uint32_t if_no, struct ether_addr *client_mac,
             uint16_t reason, bool deauth, uint32_t ban_time)
{
    struct monitoring_context *cur, *dst = NULL;
    char macaddrstr[20];
    int ret;

    list_for_each_entry(cur, &mon_list, list) {
        if (cur->if_no == if_no) {
            dst = cur;
            break;
        }
    }

    if (!dst) {
        fprintf(stderr, "Could not delete client: not found\n");
        return -1;
    }

    ether_ntoa_r(client_mac, macaddrstr);

    blob_buf_init(&b, 0);
    blobmsg_add_string(&b, "addr", macaddrstr);
    blobmsg_add_u16(&b, "reason", reason);
    blobmsg_add_u8(&b, "deauth", (uint8_t) deauth);
    blobmsg_add_u32(&b, "ban_time", ban_time);
    ret = ubus_invoke(ctx, dst->obj_id, "del_client", b.head, NULL, NULL,
                      3000);

    if (ret)
        fprintf(stderr, "Could not remove client: %s\n", ubus_strerror(ret));
    
    return ret;
}

int
ubus_set_channel(uint32_t if_no, uint32_t freq, uint32_t bcn_count)
{
    int ret;
    struct monitoring_context *cur_ctx;

    list_for_each_entry(cur_ctx, &mon_list, list) {
        if (cur_ctx->if_no != if_no)
            continue;

        blob_buf_init(&b, 0);
        blobmsg_add_u32(&b, "freq", freq);
        blobmsg_add_u32(&b, "bcn_count", bcn_count);
        ret = ubus_invoke(ctx, cur_ctx->obj_id, "switch_chan", b.head, NULL, NULL,
                          3000);
        if (ret)
            fprintf(stderr, "Failed to set channel at %s: %s\n", cur_ctx->name,
                    ubus_strerror(ret));

        return ret;
    }

    return -1;
}

static int
parse_wireless_device_interfaces(struct ap_info **aps, size_t *n_aps,
                                 struct blob_attr *ifs, size_t len)
{
    enum {
        WDEV_IF_IFNAME,
        WDEV_IF_CONFIG,
        __WDEV_IF_MAX
    };

    static const struct blobmsg_policy wdev_if_policy[__WDEV_IF_MAX] = {
        [WDEV_IF_IFNAME] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
        [WDEV_IF_CONFIG] = { .name = "config", .type = BLOBMSG_TYPE_TABLE },
    };

    enum {
        WDEV_IF_CFG_MODE,
        WDEV_IF_CFG_SSID,
        WDEV_IF_CFG_CRYPTO,
        __WDEV_IF_CFG_MAX
    };

    static const struct blobmsg_policy wdev_if_cfg_policy[__WDEV_IF_CFG_MAX] = {
         [WDEV_IF_CFG_MODE] = { .name = "mode", .type = BLOBMSG_TYPE_STRING },
         [WDEV_IF_CFG_SSID] = { .name = "ssid", .type = BLOBMSG_TYPE_STRING },
         [WDEV_IF_CFG_CRYPTO] = { 
            .name = "encryption", 
            .type = BLOBMSG_TYPE_STRING 
         },
    };

    struct info_buf if_buffer = INFO_BUF_INIT(struct ap_info);
    struct ap_info cur_ap;

    struct blob_attr *tb_cfg[__WDEV_IF_CFG_MAX], *tb_if[__WDEV_IF_MAX];
    struct blob_attr *cur;
    int ret, rem = len;

    rem = len;
    __blob_for_each_attr(cur, ifs, rem) {
        ret = blobmsg_parse(wdev_if_policy, __WDEV_IF_MAX, tb_if,
                            blobmsg_data(cur), blobmsg_len(cur));

        if (ret || !tb_if[WDEV_IF_CONFIG])
            goto parse_error;

        ret = blobmsg_parse(wdev_if_cfg_policy, __WDEV_IF_CFG_MAX, tb_cfg,
                            blobmsg_data(tb_if[WDEV_IF_CONFIG]),
                            blobmsg_len(tb_if[WDEV_IF_CONFIG]));
        if (ret || !tb_cfg[WDEV_IF_CFG_MODE])
            goto parse_error;

        // skip non-AP interfaces and interfaces without a name (down)
        if (strcmp(blobmsg_get_string(tb_cfg[WDEV_IF_CFG_MODE]), "ap") || !
            tb_if[WDEV_IF_IFNAME])
            continue;

        if(!tb_cfg[WDEV_IF_CFG_SSID])
            goto parse_error;

        memset(&cur_ap, 0, sizeof(struct ap_info));

        cur_ap.name = malloc(strlen(
            blobmsg_get_string(tb_if[WDEV_IF_IFNAME])) + 1);
        if (!cur_ap.name)
            goto out_of_mem;

        strcpy(cur_ap.name, blobmsg_get_string(tb_if[WDEV_IF_IFNAME]));
        cur_ap.ifindex = if_nametoindex(cur_ap.name);
        nl_get_mac_address(&cur_ap.bssid, cur_ap.ifindex);

        cur_ap.ssid_len = strlen(blobmsg_get_string(tb_cfg[WDEV_IF_CFG_SSID]));

        strcpy(cur_ap.ssid,
               (unsigned char *) blobmsg_get_string(tb_cfg[WDEV_IF_CFG_SSID]));

        if (tb_cfg[WDEV_IF_CFG_CRYPTO] && strcmp("none",
                blobmsg_get_string(tb_cfg[WDEV_IF_CFG_CRYPTO])))
            cur_ap.encrypted = true;

        info_buf_append(&if_buffer, &cur_ap);
    }

    *n_aps = if_buffer.n_el;
    *aps = (struct ap_info*) if_buffer.buf;

    return 0;

parse_error:
    fprintf(stderr, "Failed to parse interfaces\n");
    *aps = NULL;
    *n_aps = 0;
    return -1;

out_of_mem:
    // TODO: cleanup of info_buf content
    *aps = NULL;
    *n_aps = 0;
    fprintf(stderr, "Failed to allocate memory for AP info struct\n");
    return -1;
}

static int
_parse_path(char *path, struct wdev_info *wdev)
{
    wdev->path = malloc(strlen(path) + 1);
    if (!wdev->path) {
        fprintf(stderr, "Failed to allocate memory for PCI path\n");
        return -1;
    }

    strcpy(wdev->path, path);

    return 0;

error_unexpected_format:
    printf("Unexpected slot number format in %s\n", path);
    return -1;
}

static int
parse_wireless_device_config(struct wdev_info *wdev, struct blob_attr *cfg,
    size_t len)
{
    enum {
        WDEV_CFG_CHANNEL,
        WDEV_CFG_HWMODE,
        WDEV_CFG_PATH,
        WDEV_CFG_DISABLED,
        __WDEV_CFG_MAX
    };

    static const struct blobmsg_policy wdev_cfg_policy[__WDEV_CFG_MAX] = {
        [WDEV_CFG_CHANNEL] = { .name = "channel", .type = BLOBMSG_TYPE_STRING },
        [WDEV_CFG_HWMODE] = { .name = "hwmode", .type = BLOBMSG_TYPE_STRING },
        [WDEV_CFG_PATH] = { .name = "path", .type = BLOBMSG_TYPE_STRING },
        [WDEV_CFG_DISABLED] = { .name = "disabled", .type = BLOBMSG_TYPE_BOOL },
    };

    struct blob_attr *tb[__WDEV_CFG_MAX];
    int ret;

    ret = blobmsg_parse(wdev_cfg_policy, __WDEV_CFG_MAX, tb, cfg, len);
    if (ret || !tb[WDEV_CFG_CHANNEL] || !tb[WDEV_CFG_HWMODE] ||
        !tb[WDEV_CFG_PATH] || !tb[WDEV_CFG_DISABLED])
        goto parse_error;

    wdev->channel = atoi(blobmsg_get_string(tb[WDEV_CFG_CHANNEL]));
    if (_parse_path(blobmsg_get_string(tb[WDEV_CFG_PATH]), wdev))
        goto parse_error;

    return 0;

parse_error:
    fprintf(stderr, "Failed to parse config for wireless device '%s\n",
        wdev->name);
    return -1;
}

struct get_wireless_info_cb_args {
    struct wdev_info *devs;
    size_t n_devs;
};

static int
parse_wireless_device_table(struct get_wireless_info_cb_args *args,
                            struct blob_attr *devtable, size_t len)
{
    struct info_buf device_buffer = INFO_BUF_INIT(struct wdev_info);

    struct wdev_info cur_dev_info;
    struct blob_attr *cur_dev, *cur_attr;
    void *data;
    int ret, rem = len, data_len;

    // parse data
    rem = len;
    __blob_for_each_attr(cur_dev, devtable, rem) {

        cur_dev_info.name = malloc(strlen(blobmsg_name(cur_dev)) + 1);
        if (!cur_dev_info.name)
            goto out_of_mem_inner;

        strcpy(cur_dev_info.name, blobmsg_name(cur_dev));

        data = blobmsg_data(cur_dev);
        data_len = blobmsg_data_len(cur_dev);

        __blob_for_each_attr(cur_attr, data, data_len) {
            switch (blobmsg_type(cur_attr)) {
            case BLOBMSG_TYPE_BOOL:
                if (!strcmp(blobmsg_name(cur_attr), "up")) {
                    cur_dev_info.up = blobmsg_get_bool(cur_attr);
                } else if (!strcmp(blobmsg_name(cur_attr), "disabled")) {
                    cur_dev_info.disabled = blobmsg_get_bool(cur_attr);
                }
                break;
            case BLOBMSG_TYPE_TABLE:
                if (!strcmp(blobmsg_name(cur_attr), "config")) {
                    parse_wireless_device_config(&cur_dev_info,
                        blobmsg_data(cur_attr), blobmsg_data_len(cur_attr));
                }
                break;
            case BLOBMSG_TYPE_ARRAY:
                if (!strcmp(blobmsg_name(cur_attr), "interfaces")) {
                    parse_wireless_device_interfaces(&cur_dev_info.aps,
                        &cur_dev_info.n_aps, blobmsg_data(cur_attr),
                        blobmsg_data_len(cur_attr));
                }
            default:
                continue;
            }
        }

        info_buf_append(&device_buffer, &cur_dev_info);
    }

    args->devs = (struct wdev_info*) device_buffer.buf;
    args->n_devs = device_buffer.n_el;

    return 0;

parse_error:
    fprintf(stderr, "Failed to parse wireless device '%s'\n",
        cur_dev_info.name);
    free(args->devs);
    args->devs = NULL;
    args->n_devs = 0;
    return -1;

out_of_mem_inner:
    // TODO: cleanup of name buffers of devices
    free(args->devs);

out_of_mem: 
    fprintf(stderr, "Failed to allocate memory for wireless device\n");
    args->n_devs = 0;
    args->devs = NULL;
    return -1;
}

static void
get_wireless_info_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    parse_wireless_device_table(req->priv, blobmsg_data(msg),
                                blobmsg_data_len(msg));
}

int
ubus_get_wireless_info(struct wdev_info **devs, size_t *n_devs)
{
    int ret;

    if (!devs)
        goto error;

    struct get_wireless_info_cb_args cb_args;

    blob_buf_init(&b, 0);
    ret = ubus_invoke(ctx, wireless_id, "status", b.head,
        get_wireless_info_cb, &cb_args, 3000);
    if (ret)
        goto str_error;

    *devs = cb_args.devs;
    *n_devs = cb_args.n_devs;

    return 0;

str_error:
    fprintf(stderr, "ubus call failed: %s\n", ubus_strerror(ret));

error:
    return -1;
}

static int subscribe(struct monitoring_context *sub);

static void
wait_cb(struct ubus_context *ctx, struct ubus_event_handler *ev_handler,
        const char *type, struct blob_attr *msg)
{
    static const struct blobmsg_policy wait_policy = {
        "path", BLOBMSG_TYPE_STRING
    };

    struct blob_attr *attr;
    const char *path;
    struct monitoring_context *sub = container_of(ev_handler,
        struct monitoring_context, wait_handler);

    if (strcmp(type, "ubus.object.add"))
        return;

    blobmsg_parse(&wait_policy, 1, &attr, blob_data(msg), blob_len(msg));
    if (!attr)
        return;

    path = blobmsg_data(attr);

    // skip 'hostapd.' portion of name
    path = strchr(path, '.');
    if (!path)
        return;

    if (strcmp(sub->name, path + 1))
        return;

    subscribe(sub);
}

static inline int
subscription_wait(struct ubus_event_handler *handler)
{
    return ubus_register_event_handler(ctx, handler, "ubus.object.add");
}

static int
subscribe(struct monitoring_context *sub)
{
    static char obj_name_buf[sizeof("hostapd.") + IF_NAMESIZE + 1]; 

    int ret;

    if (sub->subscribed)
        return 0;

    sprintf(obj_name_buf, "hostapd.%s", sub->name);

    ret = ubus_lookup_id(ctx, obj_name_buf, &sub->obj_id);
    if (ret)
        goto wait;

    ret = ubus_subscribe(ctx, &sub->subscriber, sub->obj_id);
    if (ret)
        goto wait;

    printf("subscribed to ubus object: %s\n", obj_name_buf);
    sub->subscribed = true;

    return ret;

wait:
    subscription_wait(&sub->wait_handler);
    return ret;
}

static void
monitor_remove_handler(struct ubus_context *ctx,
                       struct ubus_subscriber *subscriber, uint32_t id)
{
    struct monitoring_context *sub = container_of(subscriber,
        struct monitoring_context, subscriber);

    if (sub->obj_id != id)
        return;

    printf("%s has disappeared, monitoring stopped until it reappears\n",
           sub->name);

    sub->subscribed = false;
    subscription_wait(&sub->wait_handler);
}

static int
handle_assoc(struct ubus_context *ctx, struct ubus_request_data *req,
            struct blob_attr **tb)
{
    blob_buf_init(&b, 0);
    ubus_send_reply(ctx, req, b.head);
    return 0;
}

static void
deferred_request_timeout_cb(struct pending_event *ev)
{
    wlanflow_stop_timeout(ev->timeout_cb, ev);
    list_del(&ev->list);
    free(ev);
}

/* Postpone ubus reply to 802.11 management frame event sent by hostapd.
 * The controller's reply will trigger the response.
 * If the controller does not respond within DEFERRED_REQUEST_TIMEOUT_MS ms,
 * the event is deleted.
 */
static int
defer_request(struct ubus_context *ubus_ctx, struct monitoring_context *mon_ctx,
              const char *type, uint32_t xid, struct ubus_request_data *req)
{
    struct pending_event *ev = malloc(sizeof(struct pending_event));
    if (!ev)
        return -ENOMEM;

    ev->xid = xid;
    strncpy(ev->type, type, 16);
    ev->timeout_cb = (event_timeout_cb) deferred_request_timeout_cb;
    ubus_defer_request(ubus_ctx, req, &ev->req);
    list_add(&ev->list, &mon_ctx->pending_events);

    wlanflow_start_timeout((event_timeout_cb) deferred_request_timeout_cb, ev,
                           DEFERRED_REQUEST_TIMEOUT_MS);

    return 0;
}

static int
handle_frame(struct ubus_context *ctx, struct ubus_object *obj,
            struct ubus_request_data *req, const char *method,
            struct blob_attr *msg)
{
    enum {
        PROBE_ATTR_ADDR,
        PROBE_ATTR_TARGET,
        PROBE_ATTR_SIGNAL,
        PROBE_ATTR_FREQ,
        __PROBE_ATTR_MAX,
    };

    static const struct blobmsg_policy probe_policy[__PROBE_ATTR_MAX] = {
        [PROBE_ATTR_ADDR] = { .name = "address", .type = BLOBMSG_TYPE_STRING },
        [PROBE_ATTR_TARGET] = { .name = "target", .type = BLOBMSG_TYPE_STRING },
        [PROBE_ATTR_SIGNAL] = { .name = "signal", .type = BLOBMSG_TYPE_INT32 },
        [PROBE_ATTR_FREQ] = { .name = "freq", .type = BLOBMSG_TYPE_INT32 },
    };

    int ret;
    struct blob_attr *tb[__PROBE_ATTR_MAX];
    struct monitoring_context *mon_ctx;
    struct ubus_subscriber *subscriber;
    uint32_t xid;

    ret = blobmsg_parse(probe_policy, __PROBE_ATTR_MAX, tb, blobmsg_data(msg),
            blobmsg_len(msg));
    if (ret)
        return UBUS_STATUS_INVALID_ARGUMENT;

    if (!tb[PROBE_ATTR_ADDR] ||
        !tb[PROBE_ATTR_FREQ]) {
        return UBUS_STATUS_INVALID_ARGUMENT;
    }

    subscriber = container_of(obj, struct ubus_subscriber, obj);
    mon_ctx = container_of(subscriber, struct monitoring_context, subscriber);

    ret = conn_send_ieee80211_mgmt(
            mon_ctx->cxn_id,
            mon_ctx->of_version,
            method,
            blobmsg_get_string(tb[PROBE_ATTR_ADDR]),
            tb[PROBE_ATTR_TARGET] ? 
                blobmsg_get_string(tb[PROBE_ATTR_TARGET]) : NULL,
            tb[PROBE_ATTR_SIGNAL] ? 
                (int) blobmsg_get_u32(tb[PROBE_ATTR_SIGNAL]) : 0xffffffff,  // TODO: what to set when no SSI present?
            blobmsg_get_u32(tb[PROBE_ATTR_FREQ]),
            mon_ctx->if_no,
            &xid
    );

    if (ret) {
        fprintf(stderr, "Sending Management Frame Message failed\n");
        return ret;
    }

    defer_request(ctx, mon_ctx, method, xid, req);
    return 0;
}

int
ubus_mon_init(char *ifname, uint32_t if_no, struct ether_addr *bssid,
              uint32_t channel, int cxn_id, int of_version, bool encrypted)
{
    static size_t sub_obj_name_base_len = sizeof("wlanflow.");

    int ret;
    char *sub_obj_name;
    struct monitoring_context *sub = calloc_a(sizeof(struct monitoring_context),
                                              &sub_obj_name,
                                              sub_obj_name_base_len +
                                              strlen(ifname) + 1);
    if (!sub) {
        fprintf(stderr, "Failed to allocate resources for ubus subscription to"
            "hostapd.%s\n", ifname);
        return -1;
    }

    strncpy(sub->name, ifname, IF_NAMESIZE);
    sub->cxn_id = cxn_id;
    sub->of_version = of_version;
    sub->if_no = if_no;
    sub->channel = channel;
    memcpy(&sub->bssid, bssid, ETH_ALEN);
    sub->encrypted = encrypted;
    INIT_LIST_HEAD(&sub->list);
    sub->obj_id = 0;
    sub->subscribed = false;
    sub->wait_handler.cb = wait_cb;
    INIT_LIST_HEAD(&sub->pending_events);

    sprintf(sub_obj_name, "wlanflow.%s", ifname);
    sub->subscriber.obj.name = sub_obj_name;
    sub->subscriber.obj.type = &mon_obj_type;
    sub->subscriber.obj.methods = NULL;
    sub->subscriber.obj.n_methods = 0;

    sub->subscriber.cb = handle_frame;
    sub->subscriber.remove_cb = monitor_remove_handler;

    ret = ubus_register_subscriber(ctx, &sub->subscriber);
    if (ret) {
        fprintf(stderr, "failed to register subscriber %s for %s: %s\n",
                sub->subscriber.obj.name, sub->name, ubus_strerror(ret));
        return ret;
    }

    list_add(&sub->list, &mon_list);

    ret = subscribe(sub);
    return 0;

error:
    fprintf(stderr, "Failed to initialize monitoring for %s: %s\n", ifname,
            ubus_strerror(ret));
    return ret;
}

static void
unsubscribe(struct monitoring_context *mon_ctx)
{
    if (!mon_ctx->subscribed)
        return;

    printf("unsubscribing from hostapd.%s\n", mon_ctx->name);
    ubus_unsubscribe(ctx, &mon_ctx->subscriber, mon_ctx->obj_id);
    ubus_unregister_subscriber(ctx, &mon_ctx->subscriber);
}

static void
clear_pending_events(struct list_head *ev_list)
{
    struct pending_event *cur, *next;

    list_for_each_entry_safe(cur, next, ev_list, list) {
        wlanflow_stop_timeout(cur->timeout_cb, cur);
        list_del(&cur->list);
        free(cur);
    }
}

void
ubus_mon_stop(int cxn_id)
{
    struct monitoring_context *cur, *next;

    list_for_each_entry_safe(cur, next, &mon_list, list) {
        if (cxn_id == 65536 || cur->cxn_id == cxn_id) {


            unsubscribe(cur);
            clear_pending_events(&cur->list);
            list_del(&cur->list);

            printf("Monitoring hostapd.%s stopped\n", cur->name);
            
            free(cur);
        }
    }
}

static void
get_dpid_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    static const struct blobmsg_policy dpid_policy = {
        .name = "datapath_id",
        .type = BLOBMSG_TYPE_STRING,
    };

    struct blob_attr *tb;
    int ret;

    ret = blobmsg_parse(&dpid_policy, 1, &tb, blobmsg_data(msg),
            blobmsg_len(msg));
    if (ret || !tb) {
        fprintf(stderr, "Failed to get datapath ID: %s\n", ubus_strerror(ret));
        return;
    }

    *(uint64_t*) req->priv = strtoull(blobmsg_get_string(tb), NULL, 16);
}

int
ubus_get_ovs_datapath_id(char *bridge, uint64_t *dpid)
{
    int ret;

    blob_buf_init(&b, 0);
    blobmsg_add_string(&b, "bridge", bridge);
    ret = ubus_invoke(ctx, ovsd_id, "get_datapath_id", b.head, get_dpid_cb,
            dpid, 3000);
    if (ret)
        goto error;

    return ret;

error:
    fprintf(stderr, "Failed to get datapath ID for ovs %s: %s\n",
        bridge, ubus_strerror(ret));
    return ret;
}

static void
ubus_retry_connect(void *cookie)
{
    if (ubus_reconnect(ctx, ubus_path)) {
        fprintf(stderr, "Failed to connect to ubus, retrying in %ds\n",
                UBUS_RECONNECT_TIMEOUT);
        return;
    }
    
    wlanflow_stop_timeout(ubus_retry_connect, cookie);
    
    printf("Reconnected to ubus\n");
}

static void
ubus_connection_lost_cb(struct ubus_context *ctx)
{
    wlanflow_start_timeout(ubus_retry_connect, NULL,
                           UBUS_RECONNECT_TIMEOUT * 1000);
}

static void
handle_ubus_socket(int socket_id, void *data, int read_ready, int write_ready,
                   int err)
{
    ubus_handle_event(ctx);
}

int
ubus_init(const char *path)
{
    int ret;

    if (ctx)
        return 0;

    ubus_path = path;

    ctx = ubus_connect(ubus_path);
    if (!ctx) {
        printf("ubus connection failed\n");
        return -1;
    }

    printf("connected to ubus\n");

    ctx->connection_lost = ubus_connection_lost_cb;

    ret = wlanflow_register_fd(ctx->sock.fd, handle_ubus_socket, NULL);
    if (ret) {
        fprintf(stderr, "Failed to register ubus socket with event loop\n");
        return -1;
    }

    printf("registered ubus fd with event loop\n");

    ret = ubus_add_object(ctx, &main_obj);
    if (ret) {
        fprintf(stderr, "Failed to publish ubus object\n");
        return -1;
    }

    printf("Registered with ubus\n");

    ret = ubus_lookup_id(ctx, "network.wireless", &wireless_id);
    if (ret) {
        fprintf(stderr, "Failed to look up 'network.wireless' object: %s\n",
                ubus_strerror(ret));
        return -1;
    }

    ret = ubus_lookup_id(ctx, "ovs", &ovsd_id);
    if (ret) {
        fprintf(stderr, "Failed to look up 'ovs' object: %s\n",
                ubus_strerror(ret));
    }

    return 0;
}

struct cb_args_get_info {
    struct ether_addr *client_mac;
    union station_info *client;
    bool encrypted;
};

static int
copy_client_info_cb(union station_info *s, bool last,
                    struct cb_args_get_info *args)
{
    struct stainfo *client_info;

    if (args->encrypted)
        client_info = &s->encrypted.client_info;
    else
        client_info = &s->client_info;

    if (!memcmp(&client_info->mac, args->client_mac, ETH_ALEN)) {
        memcpy(args->client, s, sizeof(union station_info));
        return FOR_ALL_CLIENTS_CB_STATUS_STOP;
    }

    return FOR_ALL_CLIENTS_CB_STATUS_CONTINUE;
}

int
ubus_get_client_info(uint32_t if_no, struct ether_addr *client_mac,
                  const char *if_name, union station_info *client)
{
    struct cb_args_get_info args = {
        .client_mac = client_mac,
        .client = client,
    };

    memset(client, 0, sizeof(union station_info));
    return ubus_run_for_all_clients(if_no, (for_all_clients_cb*) copy_client_info_cb,
                                &args);
}

void 
ubus_stop(void)
{
    struct monitoring_context *cur, *next;

    printf("shutting down ubus...");

    ubus_remove_object(ctx, &main_obj);
    
    list_for_each_entry_safe(cur, next, &mon_list, list) {
        ubus_unregister_subscriber(ctx, &cur->subscriber);
        free(cur->subscriber.obj.name);
        free(cur->name);
        free(cur);
    }

    ubus_free(ctx);

    printf("OK\n");
}

void
ubus_event_respond(uint32_t if_no, uint32_t xid, bool deny)
{
    struct monitoring_context *cur_ctx;
    struct pending_event *cur, *next;

    list_for_each_entry(cur_ctx, &mon_list, list) {

        if (if_no != cur_ctx->if_no)
            continue;

        list_for_each_entry_safe(cur, next, &cur_ctx->pending_events, list) {

            if (cur->xid != xid)
                continue;
            
            ubus_complete_deferred_request(ctx, &cur->req, deny);
            wlanflow_stop_timeout(cur->timeout_cb, cur);
            list_del(&cur->list);
            free(cur);
            return;
        }

        printf("timeout (xid=%u)\n", xid);
        return;
    }
}

int
ubus_get_ctx_for_if(const char *if_name, uint32_t if_no, uint32_t *chan,
                    int *cxn_id, int *of_version, bool *encrypted)
{
    struct monitoring_context *cur;
    bool by_ifname = if_name != NULL;

    list_for_each_entry(cur, &mon_list, list) {
        if (by_ifname) {
            if (!strcmp(if_name, cur->name))
                goto found;
        } else {
            if (cur->if_no == if_no) {
                goto found;
            }
        }
    }

    return -1;

found:
    *cxn_id = cur->cxn_id;
    *of_version = cur->of_version;
    *encrypted = cur->encrypted;
    *chan = cur->channel;
    return 0;
}

static void
get_release_desc_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    static const struct blobmsg_policy board_policy = {
        .name = "release",
        .type = BLOBMSG_TYPE_TABLE
    };

    static const struct blobmsg_policy release_policy = {
        .name = "description",
        .type = BLOBMSG_TYPE_STRING
    };

    struct blob_attr *tb_board, *tb_release;
    int ret;

    ret = blobmsg_parse(&board_policy, 1, &tb_board, blobmsg_data(msg),
                        blobmsg_len(msg));

    if (ret || !tb_board) {
        fprintf(stderr, "Failed to get board description: %s\n",
                ubus_strerror(ret));
        return;
    }

    ret = blobmsg_parse(&release_policy, 1, &tb_release, blobmsg_data(tb_board),
                        blobmsg_len(tb_board));

    if (ret || !tb_release) {
        fprintf(stderr, "Failed to get release description: %s\n",
                ubus_strerror(ret));
        return;
    }

    strcpy((char*) req->priv, blobmsg_get_string(tb_release));
}

int
ubus_get_release_desc(char *buf)
{
    
    int ret;
    uint32_t sys_obj_id;    

    ret = ubus_lookup_id(ctx, "system", &sys_obj_id);
    if (ret)
        return ret;

    ret = ubus_invoke(ctx, sys_obj_id, "board", NULL, get_release_desc_cb, buf,
        1000);
}