#include <OFConnectionManager/ofconnectionmanager_config.h>
#include <OFConnectionManager/ofconnectionmanager.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>
#include <netinet/ether.h>
#include <net/if.h>

#include <indigo/of_connection_manager.h>
#include <SocketManager/socketmanager.h>
#include <indigo/memory.h>
#include <indigo/assert.h>

#include "ofconnectionmanager_log.h"
#include "nl.h"
#include "mon.h"
#include "ubus.h"
#include "connection.h"
#include "config.h"
#include "wlanflow.h"


#define OK(op) INDIGO_ASSERT((op) == INDIGO_ERROR_NONE)

#define DEFAULT_REMOTE_PORT 0

uint16_t remote_port = DEFAULT_REMOTE_PORT;

static int controller_id;
static int ubus_fd = -1;
static pthread_mutex_t mutex;
static bool run = true;

int
wf_add_client(uint32_t if_index, struct ether_addr *client_mac,
           const char *if_name)
{
    union station_info client;
    struct stainfo *client_info;
    indigo_cxn_id_t cxn_id;
    of_version_t of_version;
    uint32_t chan;
    bool encrypted;
    int ret;

    ret = ubus_get_ctx_for_if(if_name, 0, &chan, (int*) &cxn_id,
                              (int*) &of_version, &encrypted);
    if (ret)
        goto error;

    ret = ubus_get_client_info(if_index, client_mac, if_name, &client);
    if (ret)
        goto error;

    // nl_get_mac_address(&bssid, if_index);

    if (encrypted)
        client_info = &client.encrypted.client_info;
    else
        client_info = &client.client_info;

    conn_send_add_client(cxn_id, of_version, client_info->assoc_id, client_mac, if_index,
                         client_info->capabilities, client_info->supported_rates,
                         client_info->ht_cap);

    return 0;

error:
    fprintf(stderr, "Failed to add client %s on %s\n", ether_ntoa(client_mac),
            if_name);
    return -1;
}

void
wf_del_client(uint32_t if_no, struct ether_addr* client_mac,
              const char *if_name)
{
    printf("call :: %s (client=%s, iface=%s)\n",
           __func__, ether_ntoa(client_mac), if_name);

    uint32_t chan;
    int cxn_id, of_version;
    bool encrypted;

    if (ubus_get_ctx_for_if(if_name, if_no, &chan, &cxn_id, &of_version,
                            &encrypted))
        return;

    conn_send_del_client(cxn_id, of_version, client_mac, if_no);
}

/* Dispatch appropriate message handler for controller message */
static void
cxn_msg_rx(indigo_cxn_id_t cxn_id, of_object_t *obj)
{
    switch (obj->object_id) {
    case OF_ECHO_REQUEST:
        printf("got: ECHO REQUEST\n");
        conn_handle_echo_req(cxn_id, (of_echo_request_t*) obj);
        break;
    case OF_FEATURES_REQUEST:
        printf("got: FEATURES REQUEST\n");
        conn_handle_features_req(cxn_id, (of_features_request_t*) obj);
        break;
    case OF_GET_CONFIG_REQUEST:
        printf("got: GET CONFIG REQUEST\n");
        conn_handle_get_cfg_req(cxn_id, (of_get_config_request_t*) obj);
        break;
    case OF_PORT_DESC_STATS_REQUEST:
        printf("got: PORT DESCRIPTION MULTIPART REQUEST\n");
        conn_handle_port_desc_multipart_req(cxn_id,
            (of_port_desc_stats_request_t*) obj);
        break;
    case OF_TABLE_FEATURES_STATS_REQUEST:
        printf("got: TABLE FEATURES MULTIPART REQUEST\n");
        conn_handle_table_features_multipart_req(cxn_id,
            (of_table_features_stats_request_t*) obj);
        break;
    case OF_DESC_STATS_REQUEST:
        printf("got: DESCRIPTION MULTIPART REQUEST\n");
        conn_handle_desc_multipart_req(cxn_id, (of_desc_stats_request_t*) obj);
        break;
    case OF_SDWN_GET_REMOTE_PORT_REQUEST:
        printf("got: GET REMOTE PORT REQUEST\n");
        conn_handle_sdwn_get_remote_port_req(cxn_id,
            (of_sdwn_get_remote_port_request_t*) obj);
        break;
    case OF_SDWN_ADD_CLIENT:
        printf("got: ADD CLIENT COMMAND\n");
        conn_handle_sdwn_add_client_cmd(cxn_id, (of_sdwn_add_client_t*) obj);
        break;
    case OF_SDWN_DEL_CLIENT:
        printf("got: DELETE CLIENT COMMAND\n");
        conn_handle_sdwn_del_client_cmd(cxn_id, (of_sdwn_del_client_t*) obj);
        break;
    case OF_SDWN_GET_CLIENTS_REQUEST:
        printf("got: GET CLIENTS REQUEST\n");
        conn_handle_sdwn_get_clients_req(cxn_id,
            (of_sdwn_get_clients_request_t*) obj);
        break;
    case OF_SDWN_ADD_LVAP:
        printf("got: ADD LVAP REQUEST\n");
        conn_handle_sdwn_add_lvap_cmd(cxn_id, (of_sdwn_add_lvap_t*) obj);
        break;
    case OF_SDWN_DEL_LVAP:
        printf("got: DELETE LVAP REQUEST\n");
        conn_handle_sdwn_del_lvap_cmd(cxn_id, (of_sdwn_del_lvap_t*) obj);
        break;

    case OF_SDWN_IEEE80211_MGMT_REPLY:
        // printf("got: MGMT REPLY\n");
        conn_handle_sdwn_mgmt_reply_cmd(cxn_id,
            (of_sdwn_ieee80211_mgmt_reply_t*) obj);
        break;

    case OF_SDWN_SET_CHANNEL:
        conn_handle_sdwn_set_channel_cmd(cxn_id, (of_sdwn_set_channel_t*) obj);
        break;

    case OF_METER_FEATURES_STATS_REQUEST:
        // printf("METER FEATURES REQUEST\n");
        conn_handle_meter_features_multipart_request(cxn_id,
            (of_meter_features_stats_request_t*) obj);
        break;
    case OF_PORT_STATS_REQUEST:
        // printf("PORT STATS REQUEST\n");
        conn_handle_port_stats_request(cxn_id, (of_port_stats_request_t*) obj);
        break;
    case OF_FLOW_STATS_REQUEST:
        // printf("FLOW STATS REQUEST\n");
        conn_handle_flow_stats_request(cxn_id, (of_flow_stats_request_t*) obj);
        break;
    case OF_TABLE_STATS_REQUEST:
        // printf("TABLE STATS REQUEST\n");
        conn_handle_table_stats_request(cxn_id,
            (of_table_stats_request_t*) obj);
        break;
    case OF_GROUP_STATS_REQUEST:
        // printf("GROUP STATS REQUEST\n");
        conn_handle_group_stats_request(cxn_id,
            (of_group_stats_request_t*) obj);
        // TODO
        break;
    case OF_GROUP_DESC_STATS_REQUEST:
        // printf("GROUP DESCRIPTION STATS REQUEST\n");
        // TODO
        break;
    case OF_METER_STATS_REQUEST:
        // printf("METER STATS REQUEST\n");
        conn_handle_meter_stats_request(cxn_id,
            (of_meter_stats_request_t*) obj);
        break;

    /* SDWN driver sub-handshake messages */
    case OF_SDWN_PORT_DESC_REQUEST:
        printf("got: SDWN PORT DESCRIPTION MULTIPART REQUEST\n");
        conn_handle_sdwn_port_desc_multipart_request(cxn_id,
            (of_sdwn_port_desc_request_t*) obj, &mutex);
        break;

    default:
        printf("UNKNOWN MESSAGE (Type %d)\n", obj->object_id);
    }
}

void
indigo_core_receive_controller_message(indigo_cxn_id_t cxn_id, of_object_t *obj)
{
    cxn_msg_rx(cxn_id, obj);
}

static void
handle_signal(int signo)
{
    printf("signal %d caught, shutting down...\n", signo);
    run = false;
}

/* exit on signals SIGINT, SIGTERM, SIGUSR1, SIGUSR2 */
static void
set_up_signals(void)
{
    struct sigaction s;

    memset(&s, 0, sizeof(s));
    s.sa_handler = handle_signal;
    s.sa_flags = 0;
    sigaction(SIGINT, &s, NULL);
    sigaction(SIGTERM, &s, NULL);
    sigaction(SIGUSR1, &s, NULL);
    sigaction(SIGUSR2, &s, NULL);

    s.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &s, NULL);
}

static void
socketmanager_init(void)
{
    ind_soc_config_t sock_cfg;

    INDIGO_MEM_CLEAR(&sock_cfg, sizeof(ind_soc_config_t));
    OK(ind_soc_init(&sock_cfg));
}

static int
usage(const char *progname)
{
    fprintf(stderr, "Usage: %s [options]\n"
        "Options:\n"
        " -c <controller address>:        OpenFlow controller address\n"
        " -p <controller port>:           OpenFlow controller listening port (default: %u)\n"
        " -r <remote port>:               remote port (default: %d\n"
        " -u <ubus path>:                 path to ubus socket\n"
        "\n"
        "Options are read from UCI config file (default path: /etc/config/sdwn).\n"
        "Arguments given here override config file parameters."
        "\n", progname, DEFAULT_CONTROLLER_PORT, DEFAULT_REMOTE_PORT);

    return 1;
}

int
main(int argc, char **argv)
{
    int ret, opt, ubus_fd;
    char *ctl_addr = NULL, *ubus_path = NULL;
    uint16_t ctl_port = DEFAULT_CONTROLLER_PORT;

    config_init(&ctl_addr, &ctl_port);

    while ((opt = getopt(argc, argv, "c:p:r:u:")) != -1) {
        switch (opt) {
        case 'c':
            ctl_addr = optarg;
            break;
        case 'p':
            ctl_port = atoi(optarg);
            break;
        case 'r':
            remote_port = atoi(optarg);
            break;
        case 'u':
            ubus_path = optarg;
        default:
            return usage(argv[0]);
        }
    }

    if (!ctl_addr)
        return usage(argv[0]);

    nl_init();
    socketmanager_init();
    ubus_init(ubus_path);

    controller_id = conn_init(remote_port, ctl_addr, ctl_port);
    free(ctl_addr);

    while (run) {
        ret = ind_soc_select_and_run(-1);
        if (ret) {
            fprintf(stderr, "error in event loop: %d\n", ret);
            break;
        }
    }

    ubus_stop();
    conn_stop(controller_id);

    return 0;
}

int
wlanflow_register_fd(int fd, void (*handler)(int socket_id, void *data,
                     int read_ready, int write_ready, int err), void *cookie)
{
    return ind_soc_socket_register(fd, handler, cookie);
}

int
wlanflow_unregister_fd(int fd)
{
    return ind_soc_socket_unregister(fd);
}

void
wlanflow_start_timeout(void (*handler)(void*), void *cookie, int timeout)
{
    ind_soc_timer_event_register((ind_soc_timer_callback_f) handler, cookie,
                                 timeout);
}

void
wlanflow_stop_timeout(void (*handler)(void*), void *cookie)
{
    ind_soc_timer_event_unregister(handler, cookie);
}

int
wlanflow_reload(void)
{
    int ret;
    char *ctl_addr = NULL;
    uint16_t ctl_port = DEFAULT_CONTROLLER_PORT;

    ret = conn_stop(controller_id);
    if (ret)
        return ret;

    ret = config_init(&ctl_addr, &ctl_port);
    if (ret)
        return ret;

    controller_id = conn_init(remote_port, ctl_addr, ctl_port);
    free(ctl_addr);

    return 0;
}
