libexec_PROGRAMS = nm-nebulavpn-service
nm_nebulavpn_service_SOURCES = nm-nebulavpn-service.c

nm_nebulavpn_service_CFLAGS = $(GLIB_CFLAGS) $(GIO_CFLAGS) $(NM_UTIL_CFLAGS)
nm_nebulavpn_service_LDADD = $(GLIB_LIBS) $(GIO_LIBS) $(NM_UTIL_LIBS)


nm_vpn_plugin_LTLIBRARIES = nm-nebulavpn-editor.la
nm_nebulavpn_editor_la_SOURCES = nm-nebulavpn-editor.c

nm_nebulavpn_editor_la_CFLAGS = $(GTK_CFLAGS) $(NM_CFLAGS) $(NM_UTIL_CFLAGS)
nm_nebulavpn_editor_la_LDFLAGS = -module -avoid-version
nm_nebulavpn_editor_la_LIBADD = $(GTK_LIBS) $(NM_LIBS) $(NM_UTIL_LIBS)

nm_vpn_plugin_libdir = $(nmvpn_plugin_dir)
