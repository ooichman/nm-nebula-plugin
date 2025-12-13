#include <glib.h>
#include <gio/gio.h>
#include <NetworkManager.h>
#include <nm-vpn-service-plugin.h> 
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>

// --- GLOBAL CONSTANTS ---
#define NEBULA_BINARY_PATH "/usr/bin/nebula" 
#define NEBULA_SERVICE_TYPE "nebula"

// Standard NM failure codes
#define NM_VPN_PLUGIN_FAILURE_SERVICE_FAILED NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED

// --- API DEFINITIONS ---

// Define synchronous function signatures, mimicking the style often used in stable NM plugins
typedef gboolean (*NMVpnPluginConnectFunc)(NMVpnPluginInfo *plugin, GHashTable *connection, GError **error);
typedef void (*NMVpnPluginDisconnectFunc)(NMVpnPluginInfo *plugin);

// Extern definitions for core NM plugin functions (non-prefixed, modern API)
extern NMVpnPluginInfo *nm_vpn_plugin_new(const char *service_type,
                                      NMVpnPluginConnectFunc connect_callback, 
                                      GAsyncReadyCallback connect_interactive_callback,
                                      GAsyncReadyCallback need_secrets_callback,
                                      NMVpnPluginDisconnectFunc disconnect_callback,
                                      gpointer user_data);
extern void nm_vpn_plugin_run(NMVpnPluginInfo *plugin);
extern void nm_vpn_plugin_set_ip4_config(NMVpnPluginInfo *plugin, GHashTable *ip4_config); 
extern void nm_vpn_plugin_set_state(NMVpnPluginInfo *plugin, NMVpnServiceState state);
extern void nm_vpn_plugin_failure(NMVpnPluginInfo *plugin, NMVpnPluginFailure reason); 


// --- Function Prototypes ---
static gboolean handle_connect(NMVpnPluginInfo *vpn_plugin, GHashTable *connection, GError **error);
static void handle_disconnect(NMVpnPluginInfo *vpn_plugin);


// --- Global State ---
static GPid nebula_pid = 0;
static NMVpnPluginInfo *plugin = NULL;
static gchar *temp_config_dir = NULL;


static void
report_failure(NMVpnPluginFailure reason, const char *log_message)
{
    g_warning("VPN connection failed: %s", log_message);
    nm_vpn_plugin_set_state(plugin, NM_VPN_SERVICE_STATE_INIT); 
    nm_vpn_plugin_failure(plugin, reason); 
}

// Function to clean up the temporary config file and directory
static void
cleanup_config_file()
{
    if (temp_config_dir) {
        gchar *config_file = g_build_filename(temp_config_dir, "nm_config.yml", NULL);
        if (g_file_test(config_file, G_FILE_TEST_EXISTS)) {
            g_message("Cleaning up temporary config file: %s", config_file);
            unlink(config_file);
        }
        g_free(config_file);
        
        // Optionally remove the .nebula directory if empty
        rmdir(temp_config_dir);
        
        g_free(temp_config_dir);
        temp_config_dir = NULL;
    }
}

static void
child_watch_cb(GPid pid, int status, gpointer user_data)
{
    if (pid == nebula_pid) {
        nebula_pid = 0;
        
        // Clean up the dynamically generated config file
        cleanup_config_file();

        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            g_message("Nebula process PID %d exited normally.", pid);
            nm_vpn_plugin_set_state(plugin, NM_DEVICE_STATE_DISCONNECTED); 
        } else if (WIFSIGNALED(status)) {
            g_warning("Nebula process PID %d terminated by signal %d.", pid, WTERMSIG(status));
            report_failure(NM_VPN_PLUGIN_FAILURE_SERVICE_FAILED, "Nebula process terminated unexpectedly (Signal).");
        } else {
            g_warning("Nebula process PID %d exited with status %d.", pid, WEXITSTATUS(status));
            report_failure(NM_VPN_PLUGIN_FAILURE_SERVICE_FAILED, "Nebula process exited with non-zero status.");
        }
        g_spawn_close_pid(pid);
    }
}


static gboolean
generate_nebula_config(GHashTable *connection, GError **error)
{
    GString *yaml = g_string_new("");
    gchar **lighthouses_array = NULL;
    gboolean success = FALSE;
    
    // --- 1. Retrieve Data and Paths ---
    const gchar *ca_crt = g_hash_table_lookup(connection, "ca_crt");
    const gchar *host_crt = g_hash_table_lookup(connection, "host_crt");
    const gchar *host_key = g_hash_table_lookup(connection, "host_key");
    const gchar *ip_address = g_hash_table_lookup(connection, "ip_address");
    const gchar *iface_name = g_hash_table_lookup(connection, "interface_name");
    const gchar *lighthouses_raw = g_hash_table_lookup(connection, "lighthouses");
    
    if (!ca_crt || !host_crt || !host_key || !ip_address || !iface_name) {
         g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Missing critical connection credentials.");
         goto cleanup;
    }

    gchar *ip_only = g_strndup(ip_address, strchr(ip_address, '/') - ip_address);
    if (!ip_only) ip_only = g_strdup(ip_address); 

    if (lighthouses_raw)
        lighthouses_array = g_strsplit(lighthouses_raw, "\n", 0);

    // --- 2. YAML Construction ---
    g_string_append(yaml, "pki:\n");
    g_string_append_printf(yaml, "  ca: %s\n", ca_crt);
    g_string_append_printf(yaml, "  cert: %s\n", host_crt);
    g_string_append_printf(yaml, "  key: %s\n\n", host_key);
    
    // Lighthouse definition (am_lighthouse)
    g_string_append(yaml, "lighthouse:\n");
    g_string_append(yaml, "  am_lighthouse: false\n\n");
    
    // Static Host Map Section
    g_string_append(yaml, "static_host_map:\n");
    if (lighthouses_array && lighthouses_array[0]) {
        for (gchar **ptr = lighthouses_array; *ptr; ptr++) {
            gchar *address = g_strstrip(g_strdup(*ptr));
            if (address && address[0]) {
                g_string_append_printf(yaml, "  \"%s\": [\"%s\"]\n", ip_only, address);
            }
            g_free(address);
        }
    }
    g_string_append(yaml, "\n");
    
    // Standard Config
    g_string_append(yaml, "listen:\n  host: 0.0.0.0\n  port: 0\n\n");
    g_string_append(yaml, "logging:\n  level: info\n  format: text\n\n");
    
    // TUN Section
    g_string_append(yaml, "tun:\n");
    g_string_append(yaml, "  disabled: false\n");
    g_string_append_printf(yaml, "  dev: %s\n", iface_name);
    g_string_append(yaml, "  mtu: 1400\n");
    g_string_append_printf(yaml, "  listen_address: %s\n", ip_address);
    
    // Lighthouse hosts list (used under tun:)
    g_string_append(yaml, "  lighthouse:\n");
    if (lighthouses_array && lighthouses_array[0]) {
        for (gchar **ptr = lighthouses_array; *ptr; ptr++) {
            gchar *address = g_strstrip(g_strdup(*ptr));
            if (address && address[0]) {
                g_string_append_printf(yaml, "    - %s\n", address);
            }
            g_free(address);
        }
    }
    g_string_append(yaml, "\n");

    // Firewall Section (Fixed rules based on user request)
    g_string_append(yaml, "firewall:\n");
    g_string_append(yaml, "  default_local_cidr_any: true\n");
    g_string_append(yaml, "  conntrack:\n    tcp_timeout: 12m\n    udp_timeout: 3m\n    default_timeout: 10m\n    max_connections: 100000\n");
    
    g_string_append(yaml, "\n  outbound:\n");
    g_string_append(yaml, "    - port: any\n      proto: any\n      host: any\n");
    
    g_string_append(yaml, "\n  inbound:\n");
    g_string_append(yaml, "    - port: any\n      proto: any\n      host: any\n");

    // --- 3. Write Config to User Home Directory ---
    gchar *home_dir = g_get_home_dir();
    temp_config_dir = g_build_filename(home_dir, ".nebula", NULL);
    g_mkdir_with_parents(temp_config_dir, 0700);
    gchar *config_file = g_build_filename(temp_config_dir, "nm_config.yml", NULL);
    
    if (!g_file_set_contents(config_file, yaml->str, yaml->len, error)) {
        g_critical("Failed to write Nebula config file to %s: %s", config_file, (*error)->message);
        g_free(config_file);
        goto cleanup;
    }

    g_message("Generated Nebula Config at %s:\n%s", config_file, yaml->str);
    g_free(config_file);
    success = TRUE;

cleanup:
    g_string_free(yaml, TRUE);
    g_strfreev(lighthouses_array);
    g_free(ip_only);
    g_free(home_dir);
    return success;
}

// ... handle_connect and main implementations using the new function definitions ...

static gboolean
handle_connect(NMVpnPluginInfo *vpn_plugin, 
               GHashTable *connection,
               GError **error)
{
    const GPtrArray *args;
    GError *lerror = NULL;
    const gchar *ip_address;
    gchar *ip_only = NULL;

    plugin = vpn_plugin;
    
    if (!generate_nebula_config(connection, error)) {
        return FALSE;
    }
    
    ip_address = g_hash_table_lookup(connection, "ip_address");
    ip_only = g_strndup(ip_address, strchr(ip_address, '/') - ip_address);
    if (!ip_only) ip_only = g_strdup(ip_address); 

    // Prepare arguments for the 'nebula' executable (pointing to home config)
    gchar *config_file = g_build_filename(temp_config_dir, "nm_config.yml", NULL);
    args = g_ptr_array_new();
    g_ptr_array_add(args, g_strdup(NEBULA_BINARY_PATH));
    g_ptr_array_add(args, g_strdup("-config"));
    g_ptr_array_add(args, g_strdup(config_file));
    g_ptr_array_add(args, NULL); 
    g_free(config_file);

    g_message("Launching Nebula with config: %s", config_file);
    
    if (!g_spawn_async_with_pipes(NULL, (char **)args->pdata, NULL, G_SPAWN_DO_NOT_REAP_CHILD | G_SPAWN_SEARCH_PATH, NULL, NULL, &nebula_pid, NULL, NULL, NULL, &lerror)) 
    {
        report_failure(NM_VPN_PLUGIN_FAILURE_SERVICE_FAILED, g_strdup_printf("Failed to spawn Nebula: %s", lerror->message));
        g_error_free(lerror);
        cleanup_config_file();
        goto cleanup;
    }

    // Register the child watch using the custom callback for cleanup and status updates.
    g_child_watch_add(nebula_pid, child_watch_cb, NULL); 

    // 5. Report L3 configuration to NetworkManager
    GHashTable *config = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    
    gchar *cidr_suffix = strchr(ip_address, '/');
    gchar *prefix = g_strdup(cidr_suffix ? cidr_suffix + 1 : "32");
    
    g_hash_table_insert(config, g_strdup(NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS), ip_only);
    g_hash_table_insert(config, g_strdup(NM_VPN_PLUGIN_IP4_CONFIG_PREFIX), prefix); 
    // NM typically handles the gateway and DNS, but we provide placeholders
    
    nm_vpn_plugin_set_ip4_config(plugin, (GHashTable *)config);
    g_hash_table_unref(config);

    nm_vpn_plugin_set_state(plugin, NM_VPN_SERVICE_STATE_STARTED);
    g_message("Nebula VPN connection established and configuration reported.");

cleanup:
    g_ptr_array_free(args, TRUE);
    g_free(ip_only);
    if (lerror) {
        g_propagate_error(error, lerror);
        return FALSE;
    }
    return TRUE;
}

static void
handle_disconnect(NMVpnPluginInfo *vpn_plugin)
{
    plugin = vpn_plugin;
    
    if (nebula_pid != 0) {
        g_message("Terminating Nebula process PID %d...", nebula_pid);
        if (kill(nebula_pid, SIGTERM) == -1) {
            g_warning("Failed to send SIGTERM to Nebula process: %s", g_strerror(errno));
        }
        // child_watch_cb will handle cleanup and state change
    } else {
        g_message("No active Nebula process to disconnect.");
        cleanup_config_file();
        nm_vpn_plugin_set_state(plugin, NM_DEVICE_STATE_DISCONNECTED); 
    }
}

int main(int argc, char **argv)
{
    g_type_init();
    
    plugin = nm_vpn_plugin_new(NEBULA_SERVICE_TYPE,
                               (NMVpnPluginConnectFunc)handle_connect, 
                               NULL, 
                               NULL, 
                               (NMVpnPluginDisconnectFunc)handle_disconnect, 
                               NULL);

    if (!plugin) {
        g_critical("Failed to create NMVpnPlugin.");
        return 1;
    }

    nm_vpn_plugin_run(plugin);

    g_object_unref(plugin);
    
    return 0;
}