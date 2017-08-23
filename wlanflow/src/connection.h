#ifndef CONNECTION_H_
#define CONNECTION_H_

#include <indigo/of_connection_manager.h>

#include <net/ethernet.h>
#include <pthread.h>

#include "wlanflow.h"

int conn_init(char *ctl_addr, uint16_t ctl_port);
int conn_stop(int controller_id);

/* Standard OpenFlow messages */

/* Echo Request */
int conn_handle_echo_req(indigo_cxn_id_t cxn_id, of_echo_request_t *req);

/* Features Request */
int conn_handle_features_req(indigo_cxn_id_t cxn_id, of_features_request_t *req);

/* Get Config Request */
int conn_handle_get_cfg_req(indigo_cxn_id_t cxn_id, of_get_config_request_t *req);

/* General Description Multipart Request */
int conn_handle_desc_multipart_req(indigo_cxn_id_t cxn_id, of_desc_stats_request_t *req);

/* Port Desctiption Multipart Request*/
int conn_handle_port_desc_multipart_req(indigo_cxn_id_t cxn_id, of_port_desc_stats_request_t *req);

/* Table Features - Mutlipart Request*/
int conn_handle_table_features_multipart_req(indigo_cxn_id_t cxn_id, of_table_features_stats_request_t *req);

/* Experimenter Multipart Request */
int conn_handle_experimenter_multipart_request(indigo_cxn_id_t cxn_id, of_experimenter_stats_request_t *req);

/* Meter Features Multipart Request */
int conn_handle_meter_features_multipart_request(indigo_cxn_id_t cxn_id, of_meter_features_stats_request_t *req);

/* SDWN messages */

/* SDWN Add Client Command */
int conn_handle_sdwn_add_client_cmd(indigo_cxn_id_t cxn_id, of_sdwn_add_client_t *cmd);

/* SDWN Delete Client Command*/
int conn_handle_sdwn_del_client_cmd(indigo_cxn_id_t cxn_id, of_sdwn_del_client_t *cmd);

/* SDWN Get Clients Request */
int conn_handle_sdwn_get_clients_req(indigo_cxn_id_t cxn_id, of_sdwn_get_clients_request_t *req);

/* SDWN Add LVAP Command */
int conn_handle_sdwn_add_lvap_cmd(indigo_cxn_id_t cxn_id, of_sdwn_add_lvap_t *cmd);

/* SDWN Delete LVAP Command */
int conn_handle_sdwn_del_lvap_cmd(indigo_cxn_id_t cxn_id, of_sdwn_del_lvap_t *cmd);

/* SDWN Get Channel Request */
int conn_handle_sdwn_get_channel_req(indigo_cxn_id_t cxn_id, of_sdwn_get_channel_request_t *req);

/* SDWN Set Channel Command */
int conn_handle_sdwn_set_channel_cmd(indigo_cxn_id_t cxn_id, of_sdwn_set_channel_t *cmd);

/* SDWN Probe Response Command */
int conn_handle_sdwn_mgmt_reply_cmd(indigo_cxn_id_t cxn_id, of_sdwn_ieee80211_mgmt_reply_t *cmd);

/* SDWN driver sub-handshake messages */

/* SDWN Port Description Multipart Request */
int conn_handle_sdwn_port_desc_multipart_request(indigo_cxn_id_t cxn_id, of_sdwn_port_desc_request_t *obj,
	                                             pthread_mutex_t *mutex);

/* Statistics messages */

/* Port Stats Request */
int conn_handle_port_stats_request(indigo_cxn_id_t cxn_id, of_port_stats_request_t *req);

/* Group Stats Request */
int conn_handle_group_stats_request(indigo_cxn_id_t cxn_id, of_group_stats_request_t *req);

/* Table Stats Request */
int conn_handle_table_stats_request(indigo_cxn_id_t cxn_id, of_table_stats_request_t *req);

/* Meter Stats Request */
int conn_handle_meter_stats_request(indigo_cxn_id_t cxn_id, of_meter_stats_request_t *req);

/* Flow Stats Request */
int conn_handle_flow_stats_request(indigo_cxn_id_t cxn_id, of_flow_stats_request_t *req);

/* Agent -> Controller */

/* Send of_sdwn_ieee80211_mgmt message to the controller */
int conn_send_ieee80211_mgmt(indigo_cxn_id_t cxn_id, of_version_t of_version, const char *mgmt_type,
        char *src_mac, char *dst_mac, uint32_t ssi, uint32_t freq, uint32_t if_no,
        uint32_t *xid_dst);

/* Send info about a newly connected Client to controller. */
int conn_send_add_client(indigo_cxn_id_t cxn_id, of_version_t of_version, uint32_t assoc_id,
					     struct ether_addr *client_mac, uint32_t if_no, uint16_t caps,
					     char *supported_rates, struct ieee80211_ht_cap *ht_caps);

/* Notify controller that a Client has disconnected from an AP */
int conn_send_del_client(indigo_cxn_id_t cxn_id, of_version_t of_version, struct ether_addr *client_mac,
					     uint32_t if_no);

int conn_send_get_clients_reply(indigo_cxn_id_t cxn_id, of_version_t of_version, uint32_t xid,
							 union station_info *client, bool encrypted, bool more);

uint32_t conn_next_xid(void);

#endif