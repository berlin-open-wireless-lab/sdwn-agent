#
# Copyright (C) 2010-2014 Jo-Philipp Wich <xm@subsignal.org>
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=wlanflow
PKG_RELEASE:=1

PKG_VERSION:=1

PKG_SOURCE:=$(PKG_NAME)-$(PKG_SOURCE_VERSION).tar.bz2
PKG_SOURCE_SUBDIR:=$(PKG_NAME)
PKG_SOURCE_URL:=https://github.com/berlin-open-wireless-lab/indigo.git
PKG_SOURCE_PROTO:=git
PKG_SOURCE_VERSION:=d7e6bac4a10fc9ea2f4410ac839022278a2f67d4

PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)

include $(INCLUDE_DIR)/package.mk

define Package/wlanflow
  SECTION:=utils
  CATEGORY:=Network
  DEPENDS:=+libnl +ubus +hostapd +libuci
  TITLE:=OpenFlow agent for SDWN
  MAINTAINER:=Arne Kappen <akappen@inet.tu-berlin.de>
endef

define Package/wlanflow/description
 something with openflow
endef

TARGET_CFLAGS += \
	-I$(STAGING_DIR)/usr/include/libnl3

define Build/Prepare
	$(Build/Prepare/Default)
	# copy agent source files to new 'agent' subdir in indigo repo
	mkdir -p $(PKG_BUILD_DIR)/agent
	$(CP) ./src/* $(PKG_BUILD_DIR)/agent
	# overwrite indigo Makefile with ours building just OFConnectionManger
	$(CP) ./indigo.Makefile $(PKG_BUILD_DIR)/Makefile
endef

define Package/wlanflow/install
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/agent/main $(1)/sbin/wlanflow
	$(CP) ./files/* $(1)/
endef

$(eval $(call BuildPackage,wlanflow))
