agent/main: targets/utests/OFConnectionManager/build/gcc-local/bin/utest_OFConnectionManager
	make -C agent

targets/utests/OFConnectionManager/build/gcc-local/bin/utest_OFConnectionManager:
	BUILDER_EXCLUDE_SETCAP=1 GLOBAL_CFLAGS="$(CFLAGS) -ffunction-sections -fdata-sections -fno-aggressive-loop-optimizations" make -C targets/utests/OFConnectionManager
