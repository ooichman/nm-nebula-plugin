#include <glib.h>
#include <gio/gio.h>
#include <libnm-util/nm-vpn-plugin.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>

// --- Constants ---
#define NEBULA_BINARY_PATH "/usr/bin/nebula" // MUST be installed here or in PATH
#define NEBULA_SERVICE_TYPE "nebula"
#define TEMP_CONFIG_PATH "/tmp/nebula_nm_config_%d.yml" // Dynamic temp file

// Global state for the running process
static GPid nebula_pid = 0;
static NMVpnPlugin *plugin = NULL;
static gchar *temp_config_file = NULL;

// --- Helper Functions ---

static void
report_failure(NMVpnPluginFailure reason, const char *log_message)
{
    g_warning("VPN connection failed: %s", log_message);
    nm_vpn_plugin_set_state(plugin, NM_VPN_PLUGIN_STATE_FAILURE);
    nm_vpn_plugin_set_failure(plugin, reason);
}

static void
child_watch_cb(GPid pid, int status, gpointer user_data)
{
    if (pid == nebula_pid) {
        nebula_pid = 0;
        
        // Clean up the dynamically generated config file
        if (temp_config_file) {
            if (g_file_test(temp_config_file, G_FILE_TEST_EXISTS)) {
                g_message("Cleaning up temporary config file: %s", temp_config_file);
                unlink(temp_config_file);
            }
            g_free(temp_config_file);
            temp_config_file = NULL;
        }

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
    GString *yaml;
    const char *ca_crt, *host_crt, *host_key, *ip_address, *iface_name;
    const char *lighthouses, *firewall_rules;
    gchar **lighthouses_array = NULL;
    gchar **firewall_array = NULL;
    gboolean success = FALSE;
    int fd;

    // 1. Get all config items from the NM connection
    ca_crt = g_hash_table_lookup(connection, "ca_crt");
    host_crt = g_hash_table_lookup(connection, "host_crt");
    host_key = g_hash_table_lookup(connection, "host_key");
    ip_address = g_hash_table_lookup(connection, "ip_address");
    iface_name = g_hash_table_lookup(connection, "interface_name");
    lighthouses = g_hash_table_lookup(connection, "lighthouses");
    firewall_rules = g_hash_table_lookup(connection, "firewall_rules");

    // 2. Split multi-line entries
    if (lighthouses)
        lighthouses_array = g_strsplit(lighthouses, "\n", 0);
    if (firewall_rules)
        firewall_array = g_strsplit(firewall_rules, "\n", 0);
    
    // 3. Start YAML generation
    yaml = g_string_new("");

    // PKI Section
    g_string_append(yaml, "pki:\n");
    g_string_append_printf(yaml, "  ca: %s\n", ca_crt);
    g_string_append_printf(yaml, "  cert: %s\n", host_crt);
    g_string_append_printf(yaml, "  key: %s\n\n", host_key);

    // Lighthouse Section
    g_string_append(yaml, "lighthouse:\n");
    g_string_append(yaml, "  am_lighthouse: false\n\n"); // Always false for a client plugin

    // TUN Section
    g_string_append(yaml, "tun:\n");
    g_string_append(yaml, "  disabled: false\n");
    g_string_append_printf(yaml, "  dev: %s\n", iface_name);
    g_string_append(yaml, "  mtu: 1400\n");
    g_string_append_printf(yaml, "  listen_address: %s\n", ip_address);

    // Static Host Map (required for initial lighthouse discovery)
    g_string_append(yaml, "static_host_map:\n");
    if (lighthouses_array && lighthouses_array[0]) {
        for (gchar **ptr = lighthouses_array; *ptr; ptr++) {
            gchar *address = g_strstrip(g_strdup(*ptr));
            if (address[0]) {
                // The IP address part of ip_address (e.g., 172.30.15.2/24 -> 172.30.15.2)
                gchar *ip_only = g_strndup(ip_address, strchr(ip_address, '/') - ip_address);
                g_string_append_printf(yaml, "  \"%s\": [\"%s\"]\n", ip_only, address);
                g_free(ip_only);
            }
            g_free(address);
        }
    } else {
        g_string_append(yaml, "  \"0.0.0.0\": [] # Placeholder\n");
    }

    // Lighthouse Hosts
    g_string_append(yaml, "  hosts:\n");
    if (lighthouses_array && lighthouses_array[0]) {
        for (gchar **ptr = lighthouses_array; *ptr; ptr++) {
            gchar *address = g_strstrip(g_strdup(*ptr));
            if (address[0])
                g_string_append_printf(yaml, "    - %s\n", address);
            g_free(address);
        }
    }

    // Logging/Listen (using standard defaults)
    g_string_append(yaml, "\nlisten:\n  host: 0.0.0.0\n  port: 0\n");
    g_string_append(yaml, "\nlogging:\n  level: info\n  format: text\n");
    
    // Firewall Section
    g_string_append(yaml, "\nfirewall:\n");
    g_string_append(yaml, "  default_local_cidr_any: true\n");
    g_string_append(yaml, "  conntrack:\n    tcp_timeout: 12m\n    udp_timeout: 3m\n    default_timeout: 10m\n    max_connections: 100000\n");
    
    // Firewall Rules parsing
    if (firewall_array && firewall_array[0]) {
        g_string_append(yaml, "\n  outbound:\n");
        for (gchar **ptr = firewall_array; *ptr; ptr++) {
            gchar *line = g_strstrip(g_strdup(*ptr));
            gchar **fields;
            if (line[0]) {
                // Expects: Type, Proto, Port, RemoteHost/Group
                fields = g_strsplit(line, ",", 4);
                if (fields[0] && fields[1] && fields[2] && fields[3]) {
                    gchar *type = g_strstrip(fields[0]);
                    gchar *proto = g_strstrip(fields[1]);
                    gchar *port = g_strstrip(fields[2]);
                    gchar *host = g_strstrip(fields[3]);

                    if (g_str_equal(type, "outbound")) {
                        // We assume inbound section is written below.
                    } else if (g_str_equal(type, "inbound")) {
                        // Split point for inbound rules
                        if (ptr == firewall_array || !g_str_equal(g_strstrip(g_strsplit(g_strstrip(*(ptr-1)), ",", 4)[0]), "outbound")) {
                            g_string_append(yaml, "\n  inbound:\n");
                        }
                    }

                    g_string_append(yaml, "    - port: ");
                    g_string_append(yaml, port);
                    g_string_append(yaml, "\n");
                    
                    g_string_append(yaml, "      proto: ");
                    g_string_append(yaml, proto);
                    g_string_append(yaml, "\n");
                    
                    g_string_append(yaml, "      host: ");
                    g_string_append(yaml, host);
                    g_string_append(yaml, "\n");

                    g_free(type); g_free(proto); g_free(port); g_free(host);
                } else {
                    g_warning("Skipping invalid firewall rule line: %s", line);
                }
                g_strfreev(fields);
            }
            g_free(line);
        }
    } else {
        // Fallback to allow all as per the user's sample config
        g_string_append(yaml, "  outbound:\n    - port: any\n      proto: any\n      host: any\n");
        g_string_append(yaml, "  inbound:\n    - port: any\n      proto: any\n      host: any\n");
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

    plugin = vpn_plugin;
    
    // 1. Generate the dynamic Nebula config file
    if (!generate_nebula_config(connection, error)) {
        return FALSE;
    }

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
        // Clean up temp file immediately on failure to spawn
        unlink(temp_config_file); 
        g_free(temp_config_file);
        temp_config_file = NULL;
        goto cleanup;
    }

    // 4. Set up child watch to monitor the Nebula process
    g_child_watch_add(G_PRIORITY_DEFAULT, nebula_pid, child_watch_cb, NULL);

    // 5. Report L3 configuration to NetworkManager
    // NOTE: For Nebula, the tunnel device 'nbl1' is created by Nebula itself. 
    // NetworkManager needs the L3 configuration (IP/Routes/DNS) to be pushed to it.
    // In a production plugin, you would read the output/logs of the Nebula process 
    // or probe the 'nbl1' interface to get the real assigned IP/DNS.
    // Here we hardcode a plausible setup derived from the user's config:
    GHashTable *config = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    
    // The IP address is read from the user input (e.g., 172.30.15.2/24)
    gchar *ip_addr = g_strndup(g_hash_table_lookup(connection, "ip_address"), strchr(g_hash_table_lookup(connection, "ip_address"), '/') - g_hash_table_lookup(connection, "ip_address"));
    g_hash_table_insert(config, g_strdup(NM_VPN_PLUGIN_CONFIG_IP4_ADDRESS), ip_addr);
    g_hash_table_insert(config, g_strdup(NM_VPN_PLUGIN_CONFIG_IP4_PREFIX), g_strdup("24")); 
    
    // Set a plausible Gateway (often the .1 of the subnet for overlay)
    g_hash_table_insert(config, g_strdup(NM_VPN_PLUGIN_CONFIG_IP4_GATEWAY), g_strdup("172.30.15.1"));
    
    // Add a simple DNS server (optional)
    g_hash_table_insert(config, g_strdup(NM_VPN_PLUGIN_CONFIG_DNS), g_strdup("8.8.8.8"));
    
    nm_vpn_plugin_set_ip4_config(plugin, config);
    g_hash_table_unref(config);

    // 6. Report success to NetworkManager
    nm_vpn_plugin_set_state(plugin, NM_VPN_PLUGIN_STATE_CONNECTED);
    g_message("Nebula VPN connection established and configuration reported.");

cleanup:
    g_ptr_array_free(args, TRUE);
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
