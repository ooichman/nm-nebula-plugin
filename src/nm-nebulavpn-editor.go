#include <gtk/gtk.h>
#include <glib/gi18n.h>
#include <NetworkManager.h>
#include <nm-vpn/nm-vpn-plugin-utils.h> // Editor utilities
#include <libnma/nma-ui-utils.h> // UI utilities
#include <libnm/nm.h>
#include <string.h>

#define NM_VPN_PLUGIN_NEBULA_VPN "nebula"

// Maximum number of lighthouses supported in the UI
#define MAX_LIGHTHOUSES 3

// --- Custom GTK Widget for Nebula Configuration ---

typedef struct {
    GtkWidget *main_widget;
    
    // Identity Tab Fields
    GtkWidget *cert_path_chooser;
    GtkWidget *key_path_chooser;
    GtkWidget *ca_path_chooser;
    GtkWidget *ip_address_entry;
    
    // Config Tab Fields
    GtkWidget *iface_name_entry;
    GtkWidget *lighthouse_container; // Box containing lighthouse entries
    GtkWidget *firewall_view; // GtkTextView for complex rules

    GtkWidget *lighthouse_entries[MAX_LIGHTHOUSES];

} NebulaVpnEditor;

// Helper to create a file chooser button (simplified for GTK4)
static GtkWidget *create_file_chooser_row(const gchar *title, GtkWidget **chooser_out)
{
    GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *label = gtk_label_new(title);
    
    // Use GtkFileChooserButton for certificate/key paths
    GtkWidget *chooser = gtk_file_chooser_button_new(_("Select File"), GTK_FILE_CHOOSER_ACTION_OPEN);

    gtk_widget_set_halign(label, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(hbox), label);
    gtk_box_append(GTK_BOX(hbox), chooser);

    *chooser_out = chooser;
    return hbox;
}

static GtkWidget *create_identity_page(NebulaVpnEditor *editor)
{
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 12);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 12);
    gtk_widget_set_margin_all(grid, 12); // GTK4 margin style

    gint row = 0;

    // Host Certificate Path
    GtkWidget *cert_row = create_file_chooser_row(_("Client Certificate Path (.crt):"), &editor->cert_path_chooser);
    gtk_grid_attach(GTK_GRID(grid), cert_row, 0, row++, 2, 1);

    // Host Key Path
    GtkWidget *key_row = create_file_chooser_row(_("Host Private Key Path (.key):"), &editor->key_path_chooser);
    gtk_grid_attach(GTK_GRID(grid), key_row, 0, row++, 2, 1);

    // CA Certificate Path
    GtkWidget *ca_row = create_file_chooser_row(_("CA Certificate Path (.crt):"), &editor->ca_path_chooser);
    gtk_grid_attach(GTK_GRID(grid), ca_row, 0, row++, 2, 1);

    // Client VPN IP Address
    GtkWidget *label_ip = gtk_label_new(_("Client VPN IP/CIDR (e.g., 172.30.15.2/24):"));
    editor->ip_address_entry = gtk_entry_new();
    gtk_widget_set_halign(label_ip, GTK_ALIGN_START);
    
    gtk_grid_attach(GTK_GRID(grid), label_ip, 0, row, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), editor->ip_address_entry, 1, row++, 1, 1);

    return grid;
}

static GtkWidget *create_config_page(NebulaVpnEditor *editor)
{
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_margin_all(vbox, 12);

    // --- Interface Name ---
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 6);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 12);

    editor->iface_name_entry = gtk_entry_new();
    gtk_entry_set_text(GTK_ENTRY(editor->iface_name_entry), "nbl1");
    
    GtkWidget *label_iface = gtk_label_new(_("Interface Name (tun.dev):"));
    gtk_widget_set_halign(label_iface, GTK_ALIGN_START);
    gtk_grid_attach(GTK_GRID(grid), label_iface, 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), editor->iface_name_entry, 1, 0, 1, 1);
    gtk_box_append(GTK_BOX(vbox), grid); 

    // --- Lighthouses (Up to 3 entries) ---
    GtkWidget *label_lh = gtk_label_new(_("Lighthouses (Host:Port):"));
    editor->lighthouse_container = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_widget_set_halign(label_lh, GTK_ALIGN_START);

    for (int i = 0; i < MAX_LIGHTHOUSES; i++) {
        gchar *placeholder = g_strdup_printf("Lighthouse Server %d (optional)", i + 1);
        GtkWidget *entry = gtk_entry_new();
        gtk_entry_set_placeholder_text(GTK_ENTRY(entry), placeholder);
        g_free(placeholder);
        editor->lighthouse_entries[i] = entry;
        gtk_box_append(GTK_BOX(editor->lighthouse_container), entry);
    }
    
    gtk_box_append(GTK_BOX(vbox), label_lh);
    gtk_box_append(GTK_BOX(vbox), editor->lighthouse_container);

    // --- Firewall Rules (TextView with ScrolledWindow) ---
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    editor->firewall_view = gtk_text_view_new();
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(editor->firewall_view), GTK_WRAP_WORD);
    // Placeholder text is set via buffer load/save logic

    GtkWidget *label_fw = gtk_label_new(_("Firewall Rules (Advanced YAML):"));
    gtk_widget_set_halign(label_fw, GTK_ALIGN_START);

    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), editor->firewall_view);
    
    gtk_box_append(GTK_BOX(vbox), label_fw);
    gtk_box_append(GTK_BOX(vbox), scroll);

    return vbox;
}

static void
nm_nebulavpn_editor_load(GtkWidget *widget, NMConnection *connection)
{
    NebulaVpnEditor *editor = g_object_get_data(G_OBJECT(widget), "editor_data");
    const char *setting_name = NM_SETTING_VPN;
    NMSetting *s_vpn;
    GtkTextBuffer *buffer;
    gchar **lighthouses_list = NULL;

    s_vpn = nm_connection_get_setting(connection, setting_name);
    if (!s_vpn)
        return;

    // Load Identity
    gtk_file_chooser_set_filename(GTK_FILE_CHOOSER(editor->cert_path_chooser),
                       nm_setting_vpn_get_data_item(s_vpn, "host_crt") ?: "");
    gtk_file_chooser_set_filename(GTK_FILE_CHOOSER(editor->key_path_chooser), 
                       nm_setting_vpn_get_data_item(s_vpn, "host_key") ?: "");
    gtk_file_chooser_set_filename(GTK_FILE_CHOOSER(editor->ca_path_chooser), 
                       nm_setting_vpn_get_data_item(s_vpn, "ca_crt") ?: "");
    gtk_entry_set_text(GTK_ENTRY(editor->ip_address_entry), 
                       nm_setting_vpn_get_data_item(s_vpn, "ip_address") ?: "");

    // Load Config
    gtk_entry_set_text(GTK_ENTRY(editor->iface_name_entry),
                       nm_setting_vpn_get_data_item(s_vpn, "interface_name") ?: "nbl1");

    // Load Lighthouses
    const gchar *lighthouses_raw = nm_setting_vpn_get_data_item(s_vpn, "lighthouses");
    if (lighthouses_raw)
        lighthouses_list = g_strsplit(lighthouses_raw, "\n", 0);
    
    for (int i = 0; i < MAX_LIGHTHOUSES; i++) {
        if (lighthouses_list && lighthouses_list[i]) {
            gtk_entry_set_text(GTK_ENTRY(editor->lighthouse_entries[i]), g_strstrip(g_strdup(lighthouses_list[i])));
        } else {
            gtk_entry_set_text(GTK_ENTRY(editor->lighthouse_entries[i]), "");
        }
    }
    g_strfreev(lighthouses_list);

    // Load Firewall Rules
    buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(editor->firewall_view));
    gtk_text_buffer_set_text(buffer, nm_setting_vpn_get_data_item(s_vpn, "firewall_rules") ?: 
        "# Default rules: Allow all inbound/outbound\n"
        "outbound, any, any, any\n"
        "inbound, any, any, any", -1);
}

static gboolean
nm_nebulavpn_editor_save(GtkWidget *widget, NMConnection *connection)
{
    NebulaVpnEditor *editor = g_object_get_data(G_OBJECT(widget), "editor_data");
    NMSetting *s_vpn;
    GtkTextIter start, end;
    GtkTextBuffer *buffer;
    GString *lighthouse_str = g_string_new("");

    // 1. Get simple text values
    const gchar *cert_path = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(editor->cert_path_chooser));
    const gchar *key_path = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(editor->key_path_chooser));
    const gchar *ca_path = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(editor->ca_path_chooser));
    const gchar *ip_address = gtk_entry_get_text(GTK_ENTRY(editor->ip_address_entry));
    const gchar *iface_name = gtk_entry_get_text(GTK_ENTRY(editor->iface_name_entry));

    // 2. Get Lighthouses (Combine non-empty entries)
    for (int i = 0; i < MAX_LIGHTHOUSES; i++) {
        const gchar *lh = gtk_entry_get_text(GTK_ENTRY(editor->lighthouse_entries[i]));
        if (lh && lh[0]) {
            g_string_append_printf(lighthouse_str, "%s\n", lh);
        }
    }
    
    // 3. Get Firewall Rules
    buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(editor->firewall_view));
    gtk_text_buffer_get_start_iter(buffer, &start);
    gtk_text_buffer_get_end_iter(buffer, &end);
    gchar *firewall_rules = gtk_text_buffer_get_text(buffer, &start, &end, FALSE);


    // 4. Basic validation
    if (!cert_path || !cert_path[0] || !key_path || !key_path[0] || !ip_address || !ip_address[0] || !ca_path || !ca_path[0]) {
        GtkWidget *dialog = gtk_message_dialog_new(GTK_WINDOW(gtk_widget_get_root(widget)),
                                                   GTK_DIALOG_MODAL,
                                                   GTK_MESSAGE_ERROR,
                                                   GTK_BUTTONS_OK,
                                                   _("Certificate, Key, CA Path, and IP Address are mandatory."));
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_window_destroy(GTK_WINDOW(dialog)); 
        g_free(firewall_rules);
        g_string_free(lighthouse_str, TRUE);
        return FALSE;
    }

    // 5. Get or create the VPN settings object
    s_vpn = nm_connection_get_setting(connection, NM_SETTING_VPN);
    if (!s_vpn) {
        s_vpn = g_object_new(NM_TYPE_SETTING_VPN, NULL);
        nm_connection_add_setting(connection, s_vpn);
    }

    // 6. Set the necessary properties for the service
    nm_setting_vpn_set_service_type(s_vpn, NM_VPN_PLUGIN_NEBULA_VPN);
    
    // Identity/Config
    nm_setting_vpn_set_data_item(s_vpn, "ca_crt", ca_path);
    nm_setting_vpn_set_data_item(s_vpn, "host_crt", cert_path);
    nm_setting_vpn_set_data_item(s_vpn, "host_key", key_path);
    nm_setting_vpn_set_data_item(s_vpn, "ip_address", ip_address);
    nm_setting_vpn_set_data_item(s_vpn, "interface_name", iface_name);
    
    // Complex Config data
    nm_setting_vpn_set_data_item(s_vpn, "lighthouses", lighthouse_str->str);
    nm_setting_vpn_set_data_item(s_vpn, "firewall_rules", firewall_rules);

    g_string_free(lighthouse_str, TRUE);
    g_free(firewall_rules);

    return TRUE; // Save successful
}

static GtkWidget *
nm_nebulavpn_editor_create(GtkWidget *widget)
{
    GtkWidget *notebook, *vbox;
    NebulaVpnEditor *editor = g_new0(NebulaVpnEditor, 1);

    vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    
    notebook = gtk_notebook_new();
    gtk_box_append(GTK_BOX(vbox), notebook); 

    // Page 1: Identity & IP
    GtkWidget *identity_page = create_identity_page(editor);
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), identity_page, gtk_label_new(_("Identity")));

    // Page 2: Lighthouses & Firewall
    GtkWidget *config_page = create_config_page(editor);
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), config_page, gtk_label_new(_("Networking")));

    // Store editor data on the widget for access in save/load functions
    g_object_set_data_full(G_OBJECT(vbox), "editor_data", editor, g_free);
    
    editor->main_widget = vbox;
    gtk_widget_show_all(vbox);
    
    return vbox;
}

// --- NetworkManager Plugin Entry Point ---

static GtkWidget *
nm_nebulavpn_editor_dialog_new(GtkWidget *parent_window)
{
    return nm_vpn_plugin_editor_dialog_new(parent_window,
                                           NM_VPN_PLUGIN_NEBULA_VPN,
                                           "Nebula VPN Connection",
                                           nm_nebulavpn_editor_create,
                                           nm_nebulavpn_editor_load,
                                           nm_nebulavpn_editor_save,
                                           NULL);
}

// Plugin entry function required by NetworkManager
G_MODULE_EXPORT void
nm_vpn_plugin_factory_init(NMVpnPluginFactory *factory)
{
    nm_vpn_plugin_factory_add_type(factory, 
                                   NM_VPN_PLUGIN_NEBULA_VPN, 
                                   _("Nebula Overlay Network"), 
                                   nm_nebulavpn_editor_dialog_new);
}