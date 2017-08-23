#include <OFConnectionManager/ofconnectionmanager_config.h>
#include <OFConnectionManager/ofconnectionmanager.h>
#include <SocketManager/socketmanager.h>

#include <net/if.h>

#include <indigo/of_connection_manager.h>
#include <indigo/assert.h>

#include "nl.h"
#include "ubus.h"
#include "connection.h"
#include "wlanflow.h"


#define OK(op) INDIGO_ASSERT((op) == INDIGO_ERROR_NONE)

/* Kann weg
 */
uint16_t remote_port;

static indigo_cxn_protocol_params_t protocol_params;
static indigo_cxn_config_params_t config_params;

static int
setup_cxn(char *addr, uint16_t port)
{
    indigo_controller_id_t id;

    config_params.version = OF_VERSION_1_3;

    protocol_params.tcp_over_ipv4.protocol = INDIGO_CXN_PROTO_TCP_OVER_IPV4;
    sprintf(protocol_params.tcp_over_ipv4.controller_ip, "%s", addr);
    protocol_params.tcp_over_ipv4.controller_port = port;

    OK(indigo_controller_add(&protocol_params, &config_params, &id));

    return id;
}

static void
conn_status_change(indigo_cxn_id_t cxn_id,
    indigo_cxn_protocol_params_t *cxn_proto_params,
    indigo_cxn_state_t state, void *cookie)
{
    switch (state) {
        case INDIGO_CXN_S_DISCONNECTED:
            printf("DISCONNECTED\n");
            ubus_mon_stop(cxn_id);
            break;
        case INDIGO_CXN_S_CONNECTING:
            printf("CONNECTING\n");
            break;
        case INDIGO_CXN_S_HANDSHAKE_COMPLETE:
            printf("HANDSHAKE COMPLETE\n");
            break;
        case INDIGO_CXN_S_CLOSING:
            printf("CLOSING\n");
            break;
        default:
            printf("UNKNOWN STATE\n");
    }
}

int
conn_init(uint16_t port, char *ctl_addr, uint16_t ctl_port)
{
    ind_cxn_config_t cm_cfg;

    remote_port = port;

    int ret, controller_id;    
    OK(ind_cxn_init(&cm_cfg));
    OK(indigo_cxn_status_change_register(conn_status_change, NULL));
    OK(ind_cxn_enable_set(1));
    INDIGO_ASSERT((controller_id = setup_cxn(ctl_addr, ctl_port)) >= 0);

    return controller_id;
}

int
conn_stop(int controller_id)
{
    OK(indigo_controller_remove(controller_id));

    OK(ind_cxn_enable_set(0));
    OK(ind_cxn_finish());
}

int
conn_handle_echo_req(indigo_cxn_id_t cxn_id, of_echo_request_t *req)
{
    of_echo_reply_t *reply;
    of_octets_t data;
    uint32_t xid;
    
    reply = of_echo_reply_new(req->version);
    if (reply == NULL) {
        fprintf(stderr, "Could not allocate echo response obj\n");
        return -1;
    }

    of_echo_request_data_get(req, &data);
    of_echo_reply_data_set(reply, &data);
    of_echo_request_xid_get(req, &xid);
    of_echo_reply_xid_set(reply, xid);

    indigo_cxn_send_controller_message(cxn_id, reply);

    printf("Echo reply sent\n");
    return 0;
}

int
conn_handle_features_req(indigo_cxn_id_t cxn_id, of_features_request_t *req)
{
    of_features_reply_t *reply;
    uint32_t xid;
    uint32_t capabilities = 0;
    
    if ((reply = of_features_reply_new(req->version)) == NULL) {
        printf("Could not allocate features response obj\n");
        return -1;
    }

    of_features_request_xid_get(req, &xid);
    of_features_reply_xid_set(reply, xid);
    
    union {
        struct ether_addr mac;
        uint64_t attr;
    } dpath = { .attr = 0 };

    // TODO! remove hard-coded 'eth0'
    nl_get_mac_address (&dpath.mac, if_nametoindex("eth0"));
    of_features_reply_datapath_id_set(reply, dpath.attr);
    of_features_reply_capabilities_set(reply, capabilities);
    indigo_cxn_send_controller_message(cxn_id, reply);

    printf("Features Reply sent\n");

    return 0;
}

int
conn_handle_get_cfg_req(indigo_cxn_id_t cxn_id, of_get_config_request_t *req)
{
    of_get_config_reply_t *reply;
    uint32_t xid;
    uint16_t flags = 0;
    uint16_t send_len = 0xffff;
    
    if ((reply = of_get_config_reply_new(req->version)) == NULL) {
        printf("Could not allocate config response obj\n");
        return -1;
    }

    of_get_config_request_xid_get(req, &xid);
    of_get_config_reply_xid_set(reply, xid);
    of_get_config_reply_flags_set(reply, flags);
    of_get_config_reply_miss_send_len_set(reply, send_len);
    indigo_cxn_send_controller_message(cxn_id, reply);

    printf("Get Config Reply sent\n");

    return 0;
}

int
conn_handle_desc_multipart_req(indigo_cxn_id_t cxn_id,
    of_desc_stats_request_t *req)
{
    of_desc_stats_reply_t *reply;
    uint32_t xid;
    uint16_t flags = 0;
    int ret;

    if ((reply = of_desc_stats_reply_new(req->version)) == NULL) {
        printf("Could not allocate config response obj\n");
        return -1;
    }

    char dp_desc_buf[OF_DESC_STR_LEN];

    // FIXME: driver fails to get matched in ONOS with detailed hw_desc
    ret = ubus_get_release_desc(dp_desc_buf);
    if (ret)
        sprintf(dp_desc_buf, "LEDE");

    of_desc_stats_request_xid_get(req, &xid);
    of_desc_stats_reply_xid_set(reply, xid);
    of_desc_stats_reply_flags_set(reply, flags);
    of_desc_stats_reply_mfr_desc_set(reply, "INET");
    of_desc_stats_reply_hw_desc_set(reply, "LEDE");
    of_desc_stats_reply_sw_desc_set(reply, "wlanflow");
    of_desc_stats_reply_dp_desc_set(reply, dp_desc_buf);
    
    indigo_cxn_send_controller_message(cxn_id, reply);

    printf("Description Multipart reply sent\n");

    return 0;
}

int
conn_handle_port_desc_multipart_req(indigo_cxn_id_t cxn_id,
    of_port_desc_stats_request_t *req)
{
    of_port_desc_stats_reply_t *reply;
    uint32_t xid;
    
    if ((reply = of_port_desc_stats_reply_new(req->version)) == NULL) {
        printf("Could not allocate mutlipart response obj\n");
        return -1;
    }

    of_port_desc_stats_request_xid_get(req, &xid);
    of_port_desc_stats_reply_xid_set(reply, xid);
    indigo_cxn_send_controller_message(cxn_id, reply);

    printf("Port Desc Stats Reply sent\n");

    return 0;
}

int
conn_handle_table_features_multipart_req(indigo_cxn_id_t cxn_id,
    of_table_features_stats_request_t *req)
{
    of_table_features_stats_reply_t *reply;
    uint32_t xid;
    
    if ((reply = of_table_features_stats_reply_new(req->version)) == NULL) {
        printf("Could not allocate table_features response obj\n");
        return -1;
    }

    of_table_features_stats_request_xid_get(req, &xid);
    of_table_features_stats_reply_xid_set(reply, xid);
    printf("useful information missing for OF_TABLE_FEATURES_STATS_REQUEST\n");
    indigo_cxn_send_controller_message(cxn_id, reply);

    return 0;
}

int
conn_handle_meter_features_multipart_request(indigo_cxn_id_t cxn_id,
    of_meter_features_stats_request_t *req)
{
    uint32_t xid;
    of_meter_features_stats_reply_t *reply;
    of_meter_features_t *features;

    if ((reply = of_meter_features_stats_reply_new(req->version)) == NULL) {
        printf("Failed to allocate response object\n");
        return -1;
    }

    if ((features = of_meter_features_new(req->version)) == NULL) {
        printf("Failed to allocate Meter features object\n");
        return -1;
    }

    of_meter_features_stats_request_xid_get(req, &xid);

    // TODO: meter features
    of_meter_features_max_meter_set(features, 0);
    of_meter_features_band_types_set(features, 0);
    of_meter_features_capabilities_set(features, 0);
    of_meter_features_max_bands_set(features, 0);
    of_meter_features_max_color_set(features, 0);

    of_meter_features_stats_reply_xid_set(reply, xid);
    of_meter_features_stats_reply_features_set(reply, features);

    indigo_cxn_send_controller_message(cxn_id, reply);

    printf("Meter Features reply sent\n");

    return 0;
}

int 
conn_handle_port_stats_request(indigo_cxn_id_t cxn_id,
    of_port_stats_request_t *req)
{
    uint32_t xid;
    of_port_stats_reply_t *reply = of_port_stats_reply_new(req->version);
    if (!reply) {
        fprintf(stderr, "Failed to reply to Port Stats Request\n");
        return 0;
    }

    of_port_stats_request_xid_get(req, &xid);
    of_port_stats_reply_xid_set(reply, xid);
    indigo_cxn_send_controller_message(cxn_id, reply);

    return 0;
}

int
conn_handle_group_stats_request(indigo_cxn_id_t cxn_id,
    of_group_stats_request_t *req)
{
    uint32_t xid;
    of_group_stats_reply_t *reply = of_group_stats_reply_new(req->version);
    if (!reply) {
        fprintf(stderr, "Failed to reply to Group Stats Request\n");
        return 0;
    }

    of_group_stats_request_xid_get(req, &xid);
    of_group_stats_reply_xid_set(reply, xid);
    indigo_cxn_send_controller_message(cxn_id, reply);
    return 0;
}

int
conn_handle_table_stats_request(indigo_cxn_id_t cxn_id,
    of_table_stats_request_t *req)
{
    uint32_t xid;
    of_table_stats_reply_t *reply = of_table_stats_reply_new(req->version);
    if (!reply) {
        fprintf(stderr, "Failed to reply to Table Stats Request\n");
        return 0;
    }

    of_table_stats_request_xid_get(req, &xid);
    of_table_stats_reply_xid_set(reply, xid);
    indigo_cxn_send_controller_message(cxn_id, reply);
    return 0;
}

int
conn_handle_meter_stats_request(indigo_cxn_id_t cxn_id,
    of_meter_stats_request_t *req)
{
        uint32_t xid;
    of_meter_stats_reply_t *reply = of_meter_stats_reply_new(req->version);
    if (!reply) {
        fprintf(stderr, "Failed to reply to Meter Stats Request\n");
        return 0;
    }

    of_meter_stats_request_xid_get(req, &xid);
    of_meter_stats_reply_xid_set(reply, xid);
    indigo_cxn_send_controller_message(cxn_id, reply);
    return 0;
}

int
conn_handle_flow_stats_request(indigo_cxn_id_t cxn_id, of_flow_stats_request_t *req)
{
    uint32_t xid;
    of_flow_stats_reply_t *reply = of_flow_stats_reply_new(req->version);
    if (!reply) {
        fprintf(stderr, "Failed to reply to Flow Stats Request\n");
        return 0;
    }

    of_flow_stats_request_xid_get(req, &xid);
    of_flow_stats_reply_xid_set(reply, xid);
    indigo_cxn_send_controller_message(cxn_id, reply);
    return 0;
}

uint32_t
conn_next_xid(void)
{
    static uint32_t xid = 0;
    return ++xid;
}
