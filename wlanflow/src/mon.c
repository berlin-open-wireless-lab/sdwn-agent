#include <OFConnectionManager/ofconnectionmanager_config.h>
#include <OFConnectionManager/ofconnectionmanager.h>

#include <assert.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <strings.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <netinet/ether.h>
#include <stdlib.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdbool.h>

#include "mon.h"
#include "wlanflow.h"

#define PAYLOAD_CAPTURE_LEN 3000


struct ieee80211_radiotap_header {
    unsigned char it_version;
    unsigned char it_pad;
    uint16_t it_len;    
    uint16_t it_pad2;   
    uint32_t it_present;
} __attribute__((__packed__));

/* 802.11 header */
struct ieee80211_hdr_3addr {
    uint16_t frame_ctl;
    uint16_t duration_id;
    unsigned char addr1[ETH_ALEN];
    unsigned char addr2[ETH_ALEN];
    unsigned char addr3[ETH_ALEN];
    uint16_t seq_ctl;
} __attribute__ ((__packed__));

/* Structure of the packet containing the radiotap header, IEEE 802.11 header and payload 
 */
struct packet {
  struct ieee80211_radiotap_header rtap_header;
  struct ieee80211_hdr_3addr ieee802_header;
  unsigned char payload[PAYLOAD_CAPTURE_LEN];
};

struct monitor_task {
    pthread_t thread;
    int sock_fd;
    rtap_cb *cb;
    uint32_t port;
    char ifname[IFNAMSIZ];

    bool stop;
    struct packet rcv_buf;
    indigo_cxn_id_t cxn_id;
};

static pthread_mutex_t *_mutex;
static struct monitor_task *_tasks;
static size_t _n_tasks;


static int
create_raw_socket(const char *dev)
{
    struct sockaddr_ll sll;
    struct ifreq ifr;
    int fd, ifi, rb;

    bzero(&sll, sizeof(sll)); 
    bzero(&ifr, sizeof(ifr));

    fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    assert(fd != -1);

    strncpy((char *) ifr.ifr_name, dev, IFNAMSIZ);
    ifi = ioctl(fd, SIOCGIFINDEX, &ifr);
    assert(ifi != -1);
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_family = PF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_pkttype = PACKET_OTHERHOST;
    rb = bind(fd, (struct sockaddr *) &sll, sizeof(sll));
    assert(rb != -1);

    return fd;
}

static void
packet_in_handler(indigo_cxn_id_t cxn_id, size_t len, unsigned char *data,
                  unsigned char *frame, uint32_t in_port)
{
    of_sdwn_packet_in_t *of_pkt = of_sdwn_packet_in_new(OF_VERSION_1_3);
    of_octets_t of_octets = { .data = data, .bytes = len };
    of_sdwn_packet_in_frame_set(of_pkt, &of_octets);

    of_sdwn_packet_in_hdr_version_type_set(of_pkt, frame[0]);
    of_sdwn_packet_in_hdr_flags_set(of_pkt, frame[1]);

    of_sdwn_packet_in_hdr_duration_set(of_pkt, *(uint16_t*) &frame[2]);

    of_sdwn_packet_in_hdr_addr1_set(of_pkt, *(of_mac_addr_t*) &frame[4]);
    of_sdwn_packet_in_hdr_addr2_set(of_pkt, *(of_mac_addr_t*) &frame[10]);
    of_sdwn_packet_in_hdr_addr3_set(of_pkt, *(of_mac_addr_t*) &frame[16]);

    of_sdwn_packet_in_hdr_seq_ctrl_set(of_pkt, *(uint16_t*) &frame[22]);

    of_sdwn_packet_in_hdr_addr4_set(of_pkt, *(of_mac_addr_t*) &frame[24]);
    of_sdwn_packet_in_if_no_set(of_pkt, in_port);

    // printf("%s\n", );
    // pthread_mutex_lock(_mutex);
    indigo_cxn_send_controller_message(cxn_id, of_pkt);
    // pthread_mutex_unlock(_mutex);
}

/* Wait for packets on the WLAN interface, capture them as struct packet and
 * call given argument's callback with the number of received bytes, packet and
 * radiotap header.
 */
static void*
wlan_monitor_loop(void *arg)
{
    struct monitor_task *mon_arg = (struct monitor_task*) arg;

    pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

    while(!mon_arg->stop) {
        ssize_t recvcount = recvfrom(mon_arg->sock_fd, &mon_arg->rcv_buf,
                                     sizeof(struct packet), 0, NULL, NULL);
        if (recvcount <= 0)
            continue;

        if (mon_arg->rcv_buf.rtap_header.it_len == 13) {
            //printf("assume loopback\n");
            continue;
        }

        printf("Packet-In at '%s'\n", mon_arg->ifname);

        size_t rtap_len = mon_arg->rcv_buf.rtap_header.it_len; // TODO: check bounds!

        printf("radiotap length: %d\n", rtap_len);

        mon_arg->cb(mon_arg->cxn_id, recvcount,
                    (unsigned char *) &mon_arg->rcv_buf,
                    (unsigned char *) &mon_arg->rcv_buf + rtap_len,
                    mon_arg->port);
    }

    pthread_exit(NULL);
    return NULL;

error:
    fprintf(stderr, "Failed to initialize receive buffer to monitor interface"
                    "%s\n", mon_arg->ifname);
    pthread_exit(NULL);
    return NULL;
}

int
mon_init(char **interfaces, size_t n, pthread_mutex_t *mutex,
         indigo_cxn_id_t cxn_id)
{
    // set global monitoring variables
    _tasks = calloc(n, sizeof(struct monitor_task));
    if (!_tasks)
        goto error;
    _n_tasks = n;
    _mutex = mutex;

    // spawn per-interface monitoring threads
    for (size_t i = 0; i < n; i++) {
        strncpy(_tasks[i].ifname, interfaces[i], IFNAMSIZ);
        _tasks[i].cb = packet_in_handler;
        _tasks[i].cxn_id = cxn_id;

        _tasks[i].sock_fd = create_raw_socket(interfaces[i]);
        if (_tasks[i].sock_fd != -1) {
            printf("Monitoring %s\n", interfaces[i]);
        }

        pthread_create(&_tasks[i].thread, NULL, &wlan_monitor_loop, &_tasks[i]);
    }

    return 0;

error:
    fprintf(stderr, "Failed to initialize monitoring\n");
    return -1;
}

void
mon_stop(void)
{
    for (size_t i = 0; i < _n_tasks; i++) {
        printf("Stopping monitoring thread for '%s'...", _tasks[i].ifname);
        pthread_cancel(_tasks[i].thread);
        pthread_join(_tasks[i].thread, NULL);
        printf("OK\n");
    }

    free(_tasks);
}
