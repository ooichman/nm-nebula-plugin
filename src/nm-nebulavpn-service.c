#include <glib.h>
#include <gio/gio.h>
#include <libnm-util/nm-vpn-plugin.h> // REVERTED to standard path, relying on NM_UTIL_CFLAGS
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>

// --- Constants ---
#define NEBULA_BINARY_PATH "/usr/bin/nebula" 
#define NEBULA_SERVICE_TYPE "nebula"
#define TEMP_CONFIG_PATH "/tmp/nebula_nm_config_%d.yml"

// Global state for the running process
static GPid nebula_pid = 0;
static NMVpnPlugin *plugin = NULL;
static gchar *temp_config_file = NULL;

// --- Helper Functions ---

static void
report_failure(NMVpnPluginFailure reason, const char *log_message)
{
// [Image of Linux Kernel Architecture]
    g_warning("VPN connection failed: %s", log_message);
    nm_vpn_plugin_set_state(plugin, NM_VPN_PLUGIN_STATE_FAILURE);
    nm_vpn_plugin_set_failure(plugin, reason);
}

// Function to clean up the temporary config file
static void
cleanup_config_file()
{
    if (temp_config_file) {
        if (g_file_test(temp_config_file, G_FILE_TEST_EXISTS)) {
            g_message("Cleaning up temporary config file: %s", temp_config_file);
            unlink(temp_config_file);
        }
        g_free(temp_config_file);
        temp_config_file = NULL;
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
            nm_vpn_plugin_set_state(plugin, NM_VPN_PLUGIN_STATE_DISCONNECTED);
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

// Function to dynamically generate the Nebula YAML config file
static gboolean
generate_nebula_config(GHashTable *connection, GError **error)
{
    GString *yaml = g_string_new("");
    gchar **lighthouses_array = NULL;
    gchar **firewall_array = NULL;
    gboolean success = FALSE;
    
    // 1. Get all config items from the NM connection
    const gchar *ca_crt = g_hash_table_lookup(connection, "ca_crt");
    const gchar *host_crt = g_hash_table_lookup(connection, "host_crt");
    const gchar *host_key = g_hash_table_lookup(connection, "host_key");
    const gchar *ip_address = g_hash_table_lookup(connection, "ip_address");
    const gchar *iface_name = g_hash_table_lookup(connection, "interface_name");
    const gchar *lighthouses_raw = g_hash_table_lookup(connection, "lighthouses");
    const gchar *firewall_rules_raw = g_hash_table_lookup(connection, "firewall_rules");

    if (!ca_crt || !host_crt || !host_key || !ip_address || !iface_name) {
         g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT, "Missing critical connection credentials.");
         goto cleanup;
    }

    // Determine the IP address part without CIDR (e.g., 172.30.15.2)
    gchar *ip_only = g_strndup(ip_address, strchr(ip_address, '/') - ip_address);
    if (!ip_only) ip_only = g_strdup(ip_address); // Handle case where no CIDR is present

    // 2. Split multi-line entries
    if (lighthouses_raw)
        lighthouses_array = g_strsplit(lighthouses_raw, "\n", 0);
    if (firewall_rules_raw)
        firewall_array = g_strsplit(firewall_rules_raw, "\n", 0);
    
    // --- YAML Construction ---

    // PKI Section
    g_string_append(yaml, "pki:\n");
    g_string_append_printf(yaml, "  ca: %s\n", ca_crt);
    g_string_append_printf(yaml, "  cert: %s\n", host_crt);
    g_string_append_printf(yaml, "  key: %s\n\n", host_key);

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
    } else {
        g_string_append(yaml, "  # No static lighthouses configured\n");
    }
    g_string_append(yaml, "\n");

    // Listen & Logging
    g_string_append(yaml, "listen:\n  host: 0.0.0.0\n  port: 0\n\n");
    g_string_append(yaml, "logging:\n  level: info\n  format: text\n\n");
    
    // TUN Section
    g_string_append(yaml, "tun:\n");
    g_string_append(yaml, "  disabled: false\n");
    g_string_append_printf(yaml, "  dev: %s\n", iface_name);
    g_string_append(yaml, "  mtu: 1400\n");
    g_string_append_printf(yaml, "  listen_address: %s\n", ip_address);
    
    // Lighthouse Host List
    g_string_append(yaml, "  lighthouse:\n");
    g_string_append(yaml, "    am_lighthouse: false\n"); 
    g_string_append(yaml, "    hosts:\n");
    if (lighthouses_array && lighthouses_array[0]) {
        for (gchar **ptr = lighthouses_array; *ptr; ptr++) {
            gchar *address = g_strstrip(g_strdup(*ptr));
            if (address && address[0]) {
                g_string_append_printf(yaml, "      - %s\n", address);
            }
            g_free(address);
        }
    }
    g_string_append(yaml, "\n");

    // Firewall Section
    g_string_append(yaml, "firewall:\n");
    g_string_append(yaml, "  default_local_cidr_any: true\n");
    g_string_append(yaml, "  conntrack:\n    tcp_timeout: 12m\n    udp_timeout: 3m\n    default_timeout: 10m\n    max_connections: 100000\n");
    
    g_string_append(yaml, "\n  outbound:\n");
    
    // Process Firewall Rules
    gboolean inbound_section_added = FALSE;

    if (firewall_array && firewall_array[0]) {
        for (gchar **ptr = firewall_array; *ptr; ptr++) {
            gchar *line = g_strstrip(g_strdup(*ptr));
            gchar **fields;
            if (line[0]) {
                fields = g_strsplit(line, ",", 4);
                if (fields[0] && fields[1] && fields[2] && fields[3]) {
                    gchar *type = g_strstrip(g_strdup(fields[0]));
                    gchar *proto = g_strstrip(g_strdup(fields[1]));
                    gchar *port = g_strstrip(g_strdup(fields[2]));
                    gchar *host = g_strstrip(g_strdup(fields[3]));

                    if (g_str_equal(type, "inbound") && !inbound_section_added) {
                        g_string_append(yaml, "\n  inbound:\n");
                        inbound_section_added = TRUE;
                    }
                    
                    GString *target_yaml = g_string_new("");
                    
                    g_string_append_printf(target_yaml, "    - port: %s\n", port);
                    g_string_append_printf(target_yaml, "      proto: %s\n", proto);
                    g_string_append_printf(target_yaml, "      host: %s\n", host);
                    
                    if (g_str_equal(type, "outbound")) {
                         // Must be appended to outbound section which is currently open
                         g_string_append(yaml, target_yaml->str);
                    } else if (g_str_equal(type, "inbound")) {
                         // Must be appended to inbound section which is currently open
                         g_string_append(yaml, target_yaml->str);
                    }
                    
                    g_string_free(target_yaml, TRUE);
                    g_free(type); g_free(proto); g_free(port); g_free(host);
                } else {
                    g_warning("Skipping invalid firewall rule line: %s", line);
                }
                g_strfreev(fields);
            }
            g_free(line);
        }
    } else {
        // Default rules if user left the field blank
        g_string_append(yaml, "    - port: any\n      proto: any\n      host: any\n");
        g_string_append(yaml, "\n  inbound:\n");
        g_string_append(yaml, "    - port: any\n      proto: any\n      host: any\n");
    }

    // 4. Write the YAML content to a temporary file
    temp_config_file = g_strdup_printf(TEMP_CONFIG_PATH, getpid());
    
    if (!g_file_set_contents(temp_config_file, yaml->str, yaml->len, error)) {
        g_critical("Failed to write temporary Nebula config file: %s", (*error)->message);
        goto cleanup;
    }

    g_message("Generated Nebula Config at %s:\n%s", temp_config_file, yaml->str);
    success = TRUE;

cleanup:
    g_string_free(yaml, TRUE);
    g_strfreev(lighthouses_array);
    g_strfreev(firewall_array);
    g_free(ip_only);
    return success;
}

// --- D-Bus Plugin Methods (The core of the Service) ---

static gboolean
handle_connect(NMVpnPlugin *vpn_plugin,
               GHashTable *connection,
               GError **error)
{
    const GPtrArray *args;
    GError *lerror = NULL;
    const gchar *ip_address;
    gchar *ip_only = NULL;

    plugin = vpn_plugin;
    
    // 1. Generate the dynamic Nebula config file
    if (!generate_nebula_config(connection, error)) {
        return FALSE;
    }
    
    // Get IP address details for L3 reporting
    ip_address = g_hash_table_lookup(connection, "ip_address");
    ip_only = g_strndup(ip_address, strchr(ip_address, '/') - ip_address);
    if (!ip_only) ip_only = g_strdup(ip_address); 

    // 2. Prepare arguments for the 'nebula' executable
    args = g_ptr_array_new();
    g_ptr_array_add(args, g_strdup(NEBULA_BINARY_PATH));
    g_ptr_array_add(args, g_strdup("-config"));
    g_ptr_array_add(args, g_strdup(temp_config_file));
    g_ptr_array_add(args, NULL); // NULL terminator

    // 3. Spawn the Nebula process
    g_message("Launching Nebula with config: %s", temp_config_file);
    
    if (!g_spawn_async_with_pipes(NULL,             // Working directory
                                  (char **)args->pdata, // Arguments
                                  NULL,             // Environment
                                  G_SPAWN_DO_NOT_REAP_CHILD | G_SPAWN_SEARCH_PATH,
                                  NULL,             // Child setup
                                  NULL,             // User data
                                  &nebula_pid,      // PID output
                                  NULL, NULL, NULL, // stdin/stdout/stderr
                                  &lerror)) 
    {
        report_failure(NM_VPN_PLUGIN_FAILURE_START_FAILED, g_strdup_printf("Failed to spawn Nebula: %s", lerror->message));
        g_error_free(lerror);
        cleanup_config_file();
        goto cleanup;
    }

    // 4. Set up child watch to monitor the Nebula process
    g_child_watch_add(G_PRIORITY_DEFAULT, nebula_pid, child_watch_cb, NULL);

    // 5. Report L3 configuration to NetworkManager
    GHashTable *config = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    
    // IP address is read from the user input (e.g., 172.30.15.2/24)
    gchar *cidr_suffix = strchr(ip_address, '/');
    gchar *prefix = g_strdup(cidr_suffix ? cidr_suffix + 1 : "32");
    
    g_hash_table_insert(config, g_strdup(NM_VPN_PLUGIN_CONFIG_IP4_ADDRESS), ip_only);
    g_hash_table_insert(config, g_strdup(NM_VPN_PLUGIN_CONFIG_IP4_PREFIX), prefix); 
    
    // Set a plausible Gateway (often the .1 of the subnet for overlay)
    g_hash_table_insert(config, g_strdup(NM_VPN_PLUGIN_CONFIG_IP4_GATEWAY), g_strdup("172.30.15.1"));
    g_hash_table_insert(config, g_strdup(NM_VPN_PLUGIN_CONFIG_DNS), g_strdup("8.8.8.8"));
    
    nm_vpn_plugin_set_ip4_config(plugin, config);
    g_hash_table_unref(config);

    // 6. Report success to NetworkManager
    nm_vpn_plugin_set_state(plugin, NM_VPN_PLUGIN_STATE_CONNECTED);
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
handle_disconnect(NMVpnPlugin *vpn_plugin)
{
    plugin = vpn_plugin;
    
    if (nebula_pid != 0) {
        g_message("Terminating Nebula process PID %d...", nebula_pid);
        // Send SIGTERM to the Nebula process
        if (kill(nebula_pid, SIGTERM) == -1) {
            g_warning("Failed to send SIGTERM to Nebula process: %s", g_strerror(errno));
        }
        // child_watch_cb will handle cleanup and state change
    } else {
        g_message("No active Nebula process to disconnect.");
        cleanup_config_file();
        nm_vpn_plugin_set_state(plugin, NM_VPN_PLUGIN_STATE_DISCONNECTED);
    }
}

// --- Main Service Entry Point ---

int main(int argc, char **argv)
{
    // Initialize GLib/GIO
    g_type_init();
    
    // Create the VPN service plugin instance
    plugin = nm_vpn_plugin_new(NEBULA_SERVICE_TYPE, 
                               handle_connect, 
                               NULL, // handle_connect_interactive 
                               NULL, // handle_need_secrets
                               handle_disconnect, 
                               NULL); // user_data

    if (!plugin) {
        g_critical("Failed to create NMVpnPlugin.");
        return 1;
    }

    // Run the main D-Bus loop
    nm_vpn_plugin_run(plugin);

    // Free resources
    g_object_unref(plugin);
    
    return 0;
}