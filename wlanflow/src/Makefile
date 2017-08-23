CFLAGS += -I../modules/indigo/module/inc
CFLAGS += -I../submodules/loxigen-artifacts/loci/inc
CFLAGS += -I../submodules/infra/modules/AIM/module/inc
CFLAGS += -I../modules/OFConnectionManager/module/inc
CFLAGS += -I../modules/SocketManager/module/inc
CFLAGS += -I.
CFLAGS += -DINDIGO_MEM_STDLIB
CFLAGS += -D_GNU_SOURCE

LDFLAGS += -lm -lnl-3 -lnl-genl-3 -lnl-route-3 -pthread -lubus -lubox -luci -Wl,-gc-sections

# collect static libs of OFConnectionManager
AFILES := $(shell find ../targets/utests/OFConnectionManager/build/gcc-local/lib -name '*.a')

# compile SDWN agent (wlanflow) with static libs from indigo's OFConnectionManager
main: main.o nl.o mon.o ubus.o connection-std.o connection-sdwn.o sysfs.o utils.o config.o $(AFILES)
	$(CC) $(CFLAGS) $(filter-out $(AFILES),$^) -Wl,--start-group $(AFILES) -Wl,--end-group $(LDFLAGS) -o $@
