#ifndef _CONFIG_H_
#define _CONFIG_H_

#include <inttypes.h>

#define DEFAULT_CONTROLLER_PORT 6653

int config_init(char **ipaddr, uint16_t *port);

#endif