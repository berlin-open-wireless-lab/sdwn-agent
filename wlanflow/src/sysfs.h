#ifndef SYSFS_H
#define SYSFS_H

#include <netinet/ether.h>

/* Read and write into mac the MAC address from
 * /sys/devices/<path>/ieee80211/macaddress
 */
int sysfs_path_to_mac(const char *path, struct ether_addr *mac);

/* Read and return phy name from /sys/devices/<path>/ieee80211/name.
 * Caller must free the returned string.
 */
char *sysfs_path_to_phy_name(const char *path);

/* Read and return the phy's index from /sys/class/ieee80211/<phy_name>/index.
 */
long sysfs_phy_name_to_phy_index(const char *phy_name);

/* 
 */
size_t sysfs_mac_to_phy_name(const struct ether_addr *mac, char **name);

/* Read and return all entries in /sys/class/net/ beginning with 'ovs-'
 * except 'ovs-system'. The entries are stored in 'br' and the number of
 * found entries is stored in 'n_br
 */
int sysfs_lookup_ovs_bridges(char ***br, size_t *n_br);

#endif