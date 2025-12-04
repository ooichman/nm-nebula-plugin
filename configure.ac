AC_INIT([nm-nebulavpn], [1.0.0], [your-email@example.com]) AC_CONFIG_SRCDIR([nm-nebulavpn-service.c]) AC_CONFIG_HEADERS([config.h]) AM_INIT_AUTOMAKE([foreign subdir-objects]) AC_PROG_CC AC_SUBST([VERSION])

AC_ARG_WITH([nmvpn-plugin-dir], AS_HELP_STRING([--with-nmvpn-plugin-dir=PATH], [Path to NetworkManager VPN plugin directory]), [nmvpn_plugin_dir="withval"],[nmvpnp​lugind​ir="{libdir}/NetworkManager/VPN"]) AC_SUBST([nmvpn_plugin_dir])
--- Dependency Checks ---

PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.40.0]) PKG_CHECK_MODULES([GIO], [gio-2.0 >= 2.40.0]) PKG_CHECK_MODULES([GTK], [gtk+-3.0 >= 3.20.0])

PKG_CHECK_MODULES([NM], [libnm >= 1.2.0]) PKG_CHECK_MODULES([NM_UTIL], [libnm-util >= 1.2.0])

AC_CONFIG_FILES([Makefile src/Makefile]) AC_OUTPUT
