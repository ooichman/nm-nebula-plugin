#include <gtk/gtk.h>
#include <glib/gi18n.h>
#include <libnm-util/nm-vpn-plugin-utils.h>
#include <libnm/nm.h>
#include <string.h>

// Defines the custom VPN type NetworkManager will recognize
#define NM_VPN_PLUGIN_NEBULA_VPN "nebula"

// --- Custom GTK Widget for Nebula Configuration ---

typedef struct {
    GtkWidget *main_widget;
    // Identity Tab Fields
    GtkEntry *cert_path_entry;
    GtkEntry *key_path_entry;
    GtkEntry *ip_address_entry;
    
    // Config Tab Fields
    GtkEntry *iface_name_entry;
    GtkEntry *ca_path_entry;
    GtkTextView *lighthouse_view;
    
    // Firewall View (This holds the data, but is displayed in a separate dialog)
    GtkTextView *firewall_view; 

} NebulaVpnEditor;

// Helper to create a file chooser button (simplified)
static GtkWidget *create_file_chooser_button(GtkEntry **entry)
{
    GtkWidget *hbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *file_entry = gtk_entry_new();
    GtkWidget *button = gtk_button_new_with_label(_("..."));
    
    *entry = GTK_ENTRY(file_entry);

    gtk_box_pack_start(GTK_BOX(hbox), file_entry, TRUE, TRUE, 0);
    gtk_box_pack_start(GTK_BOX(hbox), button, FALSE, FALSE, 0);
    
    return hbox;
}

static GtkWidget *create_identity_page(NebulaVpnEditor *editor)
{
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 6);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 12);
    gtk_container_set_border_width(GTK_CONTAINER(grid), 12);

    // Helper for attaching labels
    #define ATTACH_LABEL(text, row) \
        do { \
            GtkWidget *label = gtk_label_new(_(text)); \
            gtk_misc_set_alignment(GTK_MISC(label), 0.0, 0.5); \
            gtk_grid_attach(GTK_GRID(grid), label, 0, row, 1, 1); \
        } while (0)

    // Host Certificate Path
    GtkWidget *cert_hbox = create_file_chooser_button(&editor->cert_path_entry);
    ATTACH_LABEL("Client Certificate Path (.crt):", 0);
    gtk_grid_attach(GTK_GRID(grid), cert_hbox, 1, 0, 1, 1);

    // Host Key Path
    GtkWidget *key_hbox = create_file_chooser_button(&editor->key_path_entry);
    ATTACH_LABEL("Host Private Key Path (.key):", 1);
    gtk_grid_attach(GTK_GRID(grid), key_hbox, 1, 1, 1, 1);

    // CA Certificate Path 
    GtkWidget *ca_hbox = create_file_chooser_button(&editor->ca_path_entry);
    ATTACH_LABEL("CA Certificate Path (.crt):", 2);
    gtk_grid_attach(GTK_GRID(grid), ca_hbox, 1, 2, 1, 1);

    // Client VPN IP Address (e.g., 172.30.15.2/24)
    editor->ip_address_entry = GTK_ENTRY(gtk_entry_new());
    ATTACH_LABEL("Client VPN IP/CIDR (e.g., 172.30.15.2/24):", 3);
    gtk_grid_attach(GTK_GRID(grid), GTK_WIDGET(editor->ip_address_entry), 1, 3, 1, 1);
    
    #undef ATTACH_LABEL
    return grid;
}

// Handler for the Firewall configuration button
static void on_firewall_button_clicked(GtkButton *button, NebulaVpnEditor *editor)
{
    GtkWidget *dialog, *content_area, *scroll;
    GtkWidget *parent_window = gtk_widget_get_toplevel(editor->main_widget);

    // Create the modal dialog
    dialog = gtk_dialog_new_with_buttons(_("Nebula Firewall Configuration"),
                                         GTK_WINDOW(parent_window),
                                         GTK_DIALOG_MODAL | GTK_DIALOG_DESTROY_WITH_PARENT,
                                         _("_Close"),
                                         GTK_RESPONSE_CLOSE,
                                         NULL);
    
    gtk_window_set_default_size(GTK_WINDOW(dialog), 600, 400);

    content_area = gtk_dialog_get_content_area(GTK_DIALOG(dialog));
    
    // Add explanatory label
    GtkWidget *label = gtk_label_new(_("Enter structured firewall rules (one rule per line):\nFormat: Type, Proto, Port, RemoteHost/Group"));
    gtk_misc_set_padding(GTK_MISC(label), 0, 6);
    gtk_box_pack_start(GTK_BOX(content_area), label, FALSE, FALSE, 0);

    // Embed the GtkTextView (which already holds the rules buffer)
    scroll = gtk_scrolled_window_new(NULL, NULL);
    gtk_container_add(GTK_CONTAINER(scroll), GTK_WIDGET(editor->firewall_view));
    gtk_box_pack_start(GTK_BOX(content_area), scroll, TRUE, TRUE, 0);

    gtk_widget_show_all(content_area);

    gtk_dialog_run(GTK_DIALOG(dialog));
    
    // Hide the GtkTextView again, as it's owned by the editor struct
    gtk_widget_hide(GTK_WIDGET(editor->firewall_view));

    // Destroy the dialog window
    gtk_widget_destroy(dialog);
}


static GtkWidget *create_config_page(NebulaVpnEditor *editor)
{
    GtkWidget *vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 12);

    // --- Interface Name ---
    GtkWidget *grid = gtk_grid_new();
    gtk_grid_set_row_spacing(GTK_GRID(grid), 6);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 12);

    editor->iface_name_entry = GTK_ENTRY(gtk_entry_new());
    gtk_entry_set_text(editor->iface_name_entry, "nbl1");
    
    GtkWidget *label_iface = gtk_label_new(_("Interface Name (tun.dev):"));
    gtk_misc_set_alignment(GTK_MISC(label_iface), 0.0, 0.5);
    gtk_grid_attach(GTK_GRID(grid), label_iface, 0, 0, 1, 1);
    gtk_grid_attach(GTK_GRID(grid), GTK_WIDGET(editor->iface_name_entry), 1, 0, 1, 1);
    gtk_box_pack_start(GTK_BOX(vbox), grid, FALSE, FALSE, 0);

    // --- Lighthouses (Multi-line input) ---
    GtkWidget *scroll = gtk_scrolled_window_new(NULL, NULL);
    editor->lighthouse_view = GTK_TEXT_VIEW(gtk_text_view_new());
    gtk_text_view_set_wrap_mode(editor->lighthouse_view, GTK_WRAP_NONE);
    gtk_text_view_set_placeholder_text(editor->lighthouse_view, _("Enter Lighthouse addresses (Host:Port), one per line, e.g.,\n172.30.15.1:4242\nsecond.lighthouse.com:4242"));
    gtk_container_add(GTK_CONTAINER(scroll), GTK_WIDGET(editor->lighthouse_view));
    
    GtkWidget *label_lh = gtk_label_new(_("Lighthouses (static_host_map/hosts):"));
    gtk_misc_set_alignment(GTK_MISC(label_lh), 0.0, 0.5);
    gtk_box_pack_start(GTK_BOX(vbox), label_lh, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), scroll, TRUE, TRUE, 0);

    // --- Firewall Rules Button ---
    // Initialize the view but keep it hidden until the button is pressed
    editor->firewall_view = GTK_TEXT_VIEW(gtk_text_view_new());
    gtk_text_view_set_wrap_mode(editor->firewall_view, GTK_WRAP_WORD);
    gtk_text_view_set_placeholder_text(editor->firewall_view, 
        _("Structured Firewall Rules (one rule per line):\n"
          "Type, Proto, Port, RemoteHost/Group\n"
          "e.g., outbound, any, any, any\n"
          "e.g., inbound, tcp, 22, @ssh_servers"));

    GtkWidget *fw_button = gtk_button_new_with_label(_("Configure Firewall Rules..."));
    g_signal_connect(fw_button, "clicked", G_CALLBACK(on_firewall_button_clicked), editor);
    
    GtkWidget *label_fw = gtk_label_new(_("Firewall Rules:"));
    gtk_misc_set_alignment(GTK_MISC(label_fw), 0.0, 0.5);
    gtk_box_pack_start(GTK_BOX(vbox), label_fw, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(vbox), fw_button, FALSE, FALSE, 0);

    return vbox;
}

static void
nm_nebulavpn_editor_load(GtkWidget *widget, NMConnection *connection)
{
    NebulaVpnEditor *editor = g_object_get_data(G_OBJECT(widget), "editor_data");
    const char *setting_name = NM_SETTING_VPN;
    NMSetting *s_vpn;
    GtkTextBuffer *buffer;

    s_vpn = nm_connection_get_setting(connection, setting_name);
    if (!s_vpn)
        return;

    // Load Identity
    gtk_entry_set_text(editor->cert_path_entry, 
                       nm_setting_vpn_get_data_item(s_vpn, "host_crt") ?: "");
    gtk_entry_set_text(editor->key_path_entry, 
                       nm_setting_vpn_get_data_item(s_vpn, "host_key") ?: "");
    gtk_entry_set_text(editor->ca_path_entry, 
                       nm_setting_vpn_get_data_item(s_vpn, "ca_crt") ?: "");
    gtk_entry_set_text(editor->ip_address_entry, 
                       nm_setting_vpn_get_data_item(s_vpn, "ip_address") ?: "");

    // Load Config
    gtk_entry_set_text(editor->iface_name_entry,
                       nm_setting_vpn_get_data_item(s_vpn, "interface_name") ?: "nbl1");

    buffer = gtk_text_view_get_buffer(editor->lighthouse_view);
    gtk_text_buffer_set_text(buffer, nm_setting_vpn_get_data_item(s_vpn, "lighthouses") ?: "", -1);

    buffer = gtk_text_view_get_buffer(editor->firewall_view);
    gtk_text_buffer_set_text(buffer, nm_setting_vpn_get_data_item(s_vpn, "firewall_rules") ?: "", -1);
}

static gboolean
nm_nebulavpn_editor_save(GtkWidget *widget, NMConnection *connection)
{
    NebulaVpnEditor *editor = g_object_get_data(G_OBJECT(widget), "editor_data");
    NMSetting *s_vpn;
    GtkTextIter start, end;
    GtkTextBuffer *buffer;
    const char *cert_path, *key_path, *ip_address, *iface_name, *ca_path;
    char *lighthouses, *firewall_rules;

    // 1. Get simple text values
    cert_path = gtk_entry_get_text(editor->cert_path_entry);
    key_path = gtk_entry_get_text(editor->key_path_entry);
    ca_path = gtk_entry_get_text(editor->ca_path_entry);
    ip_address = gtk_entry_get_text(editor->ip_address_entry);
    iface_name = gtk_entry_get_text(editor->iface_name_entry);

    // 2. Get multi-line values
    buffer = gtk_text_view_get_buffer(editor->lighthouse_view);
    gtk_text_buffer_get_start_iter(buffer, &start);
    gtk_text_buffer_get_end_iter(buffer, &end);
    lighthouses = gtk_text_buffer_get_text(buffer, &start, &end, FALSE);

    buffer = gtk_text_view_get_buffer(editor->firewall_view);
    gtk_text_buffer_get_start_iter(buffer, &start);
    gtk_text_buffer_get_end_iter(buffer, &end);
    firewall_rules = gtk_text_buffer_get_text(buffer, &start, &end, FALSE);


    // 3. Basic validation
    if (!cert_path || !cert_path[0] || !key_path || !key_path[0] || !ip_address || !ip_address[0]) {
        GtkWidget *dialog = gtk_message_dialog_new(GTK_WINDOW(gtk_widget_get_toplevel(widget)),
                                                   GTK_DIALOG_MODAL,
                                                   GTK_MESSAGE_ERROR,
                                                   GTK_BUTTONS_OK,
                                                   _("Certificate, Key, and IP Address are mandatory."));
        gtk_dialog_run(GTK_DIALOG(dialog));
        gtk_widget_destroy(dialog);
        g_free(lighthouses);
        g_free(firewall_rules);
        return FALSE;
    }

    // 4. Get or create the VPN settings object
    s_vpn = nm_connection_get_setting(connection, NM_SETTING_VPN);
    if (!s_vpn) {
        s_vpn = g_object_new(NM_TYPE_SETTING_VPN, NULL);
        nm_connection_add_setting(connection, s_vpn);
    }

    // 5. Set the necessary properties for the service
    nm_setting_vpn_set_service_type(s_vpn, NM_VPN_PLUGIN_NEBULA_VPN);
    
    // Identity/Config
    nm_setting_vpn_set_data_item(s_vpn, "ca_crt", ca_path);
    nm_setting_vpn_set_data_item(s_vpn, "host_crt", cert_path);
    nm_setting_vpn_set_data_item(s_vpn, "host_key", key_path);
    nm_setting_vpn_set_data_item(s_vpn, "ip_address", ip_address);
    nm_setting_vpn_set_data_item(s_vpn, "interface_name", iface_name);
    
    // Complex Config data
    nm_setting_vpn_set_data_item(s_vpn, "lighthouses", lighthouses);
    nm_setting_vpn_set_data_item(s_vpn, "firewall_rules", firewall_rules);

    g_free(lighthouses);
    g_free(firewall_rules);

    return TRUE; // Save successful
}

static GtkWidget *
nm_nebulavpn_editor_create(GtkWidget *widget)
{
    GtkWidget *notebook, *vbox;
    NebulaVpnEditor *editor = g_new0(NebulaVpnEditor, 1);

    vbox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 6);
    gtk_container_set_border_width(GTK_CONTAINER(vbox), 12);
    
    notebook = gtk_notebook_new();
    gtk_box_pack_start(GTK_BOX(vbox), notebook, TRUE, TRUE, 0);

    // Page 1: Identity & IP
    GtkWidget *identity_page = create_identity_page(editor);
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), identity_page, gtk_label_new(_("Identity")));

    // Page 2: Lighthouses & Firewall
    GtkWidget *config_page = create_config_page(editor);
    gtk_notebook_append_page(GTK_NOTEBOOK(notebook), config_page, gtk_label_new(_("Networking & Firewall")));

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