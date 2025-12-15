AC_INIT([nm-nebulavpn], [1.0.0], [two.oes@gmail.com])
AC_CONFIG_SRCDIR([src/nm-nebulavpn-service.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIRS([m4])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_PROG_CC

AC_PROG_LIBTOOL
LT_INIT

AC_SUBST([VERSION])

AC_ARG_WITH([nmvpn-plugin-dir],
AS_HELP_STRING([--with-nmvpn-plugin-dir=PATH], [Path to NetworkManager VPN plugin directory]),
[nmvpn_plugin_dir="$withval"],
[nmvpn_plugin_dir="${libdir}/NetworkManager/VPN"])
AC_SUBST([nmvpn_plugin_dir])


PKG_CHECK_MODULES([GLIB], [glib-2.0 >= 2.64])
PKG_CHECK_MODULES([GIO], [gio-2.0 >= 2.64])
PKG_CHECK_MODULES([GTK], [gtk4 >= 4.0.0], [],
[AC_MSG_ERROR([Package requirements (gtk4) were not met. Install gtk4-devel.])])

PKG_CHECK_MODULES([NM], [libnm >= 1.50.3], [],
[AC_MSG_ERROR([Package requirements (libnm >= 1.50.3) were not met. Install NetworkManager-libnm-devel.])])


NM_UTIL_CFLAGS=$NM_CFLAGS
NM_UTIL_LIBS=$NM_LIBS
AC_SUBST([NM_UTIL_CFLAGS])
AC_SUBST([NM_UTIL_LIBS])

PKG_CHECK_MODULES([NM_UI], [libnma >= 1.10.6], [],
[AC_MSG_ERROR([Package requirements (libnma >= 1.10.6) were not met. Install libnma-devel.])])

NM_VPN_CFLAGS="-I/usr/include/libnm"
AC_SUBST([NM_VPN_CFLAGS])

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT