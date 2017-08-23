#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <glob.h>
#include <ctype.h>

#include "sysfs.h"

int
sysfs_path_to_mac(const char *path, struct ether_addr *mac)
{
	FILE *f;
	char buf[18];
	char *pattern;
	glob_t phy_path;
	int ret;
	struct ether_addr *tmp;

	ret = asprintf(&pattern, "/sys/devices/%s/ieee80211/*/macaddress", path);
	if (ret < 0)
		return -1;

	ret = glob(pattern, 0, NULL, &phy_path);
	if (ret)
		goto error_free_pattern;

	if (phy_path.gl_pathc != 1)
		goto error_free;

	f = fopen(phy_path.gl_pathv[0], "r");
	if (!f)
		goto error_free;

	if (!fgets(buf, 18, f))
		goto error_close;

	fclose(f);

	tmp = ether_aton(buf);
	memcpy(mac, tmp, 6);

	globfree(&phy_path);
	free(pattern);

	return 0;

error_close:
	fclose(f);

error_free_pattern:
	free(pattern);

error_free:
	globfree(&phy_path);
	return -1;
}

size_t
sysfs_mac_to_phy_name(const struct ether_addr *mac, char **name)
{
	// TODO
}

char*
sysfs_path_to_phy_name(const char *path)
{
	char *phy;
	size_t phy_namelen;
	FILE *f;
	char *pattern;
	glob_t phy_path;
	int ret;

	ret = asprintf(&pattern, "/sys/devices/%s/ieee80211/*/name", path);
	if (ret < 0)
		return NULL;

	ret = glob(pattern, 0, NULL, &phy_path);
	if (ret)
		goto error_free_pattern;

	if (phy_path.gl_pathc != 1)
		goto error_free;

	f = fopen(phy_path.gl_pathv[0], "r");
	if (!f)
		goto error_free;

	phy_namelen = 0;
	while (fgetc(f) != EOF)
		phy_namelen++;

	if (!phy_namelen)
		goto error_close;

	phy = malloc(phy_namelen + 1);
	if (!phy)
		goto error_close;

	rewind(f);
	char c;
	for (size_t i = 0; i < phy_namelen; i++) {
		c = fgetc(f);

		if (c == EOF || !isalnum(c)) {
			phy[i] = '\0';
			break;
		}
		
		phy[i] = c;
	}

	fclose(f);

	globfree(&phy_path);
	free(pattern);

	return phy;

error_close:
	fclose(f);

error_free_pattern:
	free(pattern);

error_free:
	globfree(&phy_path);
	return NULL;
}

long
sysfs_phy_name_to_phy_index(const char *phy_name)
{
	long index;
	char *path;
	char buf[16];
	FILE *f;
	int ret;

	ret = asprintf(&path, "/sys/class/ieee80211/%s/index", phy_name);
	if (ret < 0)
		return -1;

	f = fopen(path, "r");
	if (!f)
		goto error_free_path;

	if (!fgets(buf, 16, f))
		goto error_close;
	
	fclose(f);
	free(path);

	return atoi(buf);

error_close:
	fclose(f);

error_free_path:
	free(path);
	return -1;
}

int
sysfs_lookup_ovs_bridges(char ***br, size_t *n_br)
{
	int ret;
	glob_t br_glob;
	*n_br = 0;
	char *br_name;
	size_t pos = 0;
	char **buf;

	ret = glob("/sys/class/net/ovs-*", GLOB_NOSORT, NULL, &br_glob);
	if (ret)
		return ret;

	// -1 because we ignore ovs-system
	buf = calloc(br_glob.gl_pathc - 1, sizeof(char*));
	if (!buf)
		return -1;

	for (size_t i = 0; i < br_glob.gl_pathc; i++) {
		// strip leading directories
		br_name = strrchr(br_glob.gl_pathv[i], '/') + 1;

		// skip ovs-system
		if (!strcmp(br_name, "ovs-system")) {
			continue;
		}

		buf[pos] = malloc(strlen(br_name) + 1);
		if (!buf[pos]) {
			// TODO! cleanup
			return -1;
		}

		strcpy(buf[pos++], br_name);
	}

	// TODO: ignore all internal bridges
	*n_br = br_glob.gl_pathc - 1;
	*br = buf;
	globfree(&br_glob);

	return 0;
}