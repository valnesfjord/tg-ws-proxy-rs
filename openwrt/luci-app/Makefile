# SPDX-License-Identifier: MIT

include $(TOPDIR)/rules.mk

PKG_NAME:=luci-app-tg-ws-proxy-rs
PKG_VERSION:=$(if $(TG_PACKAGE_VERSION),$(TG_PACKAGE_VERSION),2.3.0)
PKG_RELEASE:=1
PKG_LICENSE:=MIT
PKG_MAINTAINER:=Lyedok

include $(INCLUDE_DIR)/package.mk

define Package/luci-app-tg-ws-proxy-rs
  SECTION:=luci
  CATEGORY:=LuCI
  SUBMENU:=3. Applications
  TITLE:=LuCI support for tg-ws-proxy-rs
  DEPENDS:=+luci-base
  PKGARCH:=all
endef

define Package/luci-app-tg-ws-proxy-rs/description
 LuCI interface and OpenWrt service integration for a separately installed
 tg-ws-proxy-rs release binary. All names are suffixed with -rs so the package
 coexists with an upstream tg-ws-proxy package on the same router.
endef

define Build/Compile
endef

define Package/luci-app-tg-ws-proxy-rs/conffiles
/etc/config/tg-ws-proxy-rs
endef

define Package/luci-app-tg-ws-proxy-rs/install
	$(INSTALL_DIR) $(1)/etc $(1)/usr/share $(1)/www
	$(CP) ./root/etc/* $(1)/etc/
	chmod 0600 $(1)/etc/config/tg-ws-proxy-rs
	$(CP) ./root/usr/share/* $(1)/usr/share/
	$(CP) ./htdocs/* $(1)/www/
endef

$(eval $(call BuildPackage,luci-app-tg-ws-proxy-rs))
