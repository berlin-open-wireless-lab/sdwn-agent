#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <uci.h>

#include "config.h"


static struct uci_context *uci_ctx;
static struct uci_package *uci_pkg;


static int
config_read(struct uci_package *pkg, char **ipaddr, uint16_t *port)
{
	const char *ipaddr_opt = NULL, *port_opt = NULL;
	struct uci_element *e;

	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);

		if (strcmp(s->type, "controller"))
			continue;

		ipaddr_opt = uci_lookup_option_string(uci_ctx, s, "ipaddr");
		port_opt = uci_lookup_option_string(uci_ctx, s, "port");

		if (!ipaddr_opt)
			return -1;

		*ipaddr = strdup(ipaddr_opt);

		if (!port_opt)
			*port = DEFAULT_CONTROLLER_PORT;
		else
			*port = atoi(port_opt);

		return 0;
	}
}

int
config_init(char **ipaddr, uint16_t *port)
{
	struct uci_context *ctx = uci_ctx;

	if (!ctx) {
		ctx = uci_alloc_context();
		uci_ctx = ctx;

		ctx->flags &= ~UCI_FLAG_STRICT;
	} else {
		uci_pkg = uci_lookup_package(ctx, "sdwn");
		if (uci_pkg)
			uci_unload(ctx, uci_pkg);
	}

	if (uci_load(ctx, "sdwn", &uci_pkg))
		return -1;

	return config_read(uci_pkg, ipaddr, port);
}
