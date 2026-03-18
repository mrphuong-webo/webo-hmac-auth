<?php
/**
 * Plugin Name: WEBO HMAC Auth
 * Description: HMAC authentication middleware for WEBO MCP and WP Abilities endpoints (multisite-ready, network admin managed API keys).
 * Version: 1.0.1
 * Author: WEBO
 * Text Domain: webo-hmac-auth
 * Requires at least: 6.0
 * Requires PHP: 7.4
 * Requires Plugins: webo-mcp
 * Network: false
 *
 * Network activation notes:
 * - Activate from Network Admin > Plugins.
 * - API key management UI is available only in Network Admin.
 * - Database table uses $wpdb->base_prefix for multisite-wide key storage.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

add_action(
	'plugins_loaded',
	'webo_hmac_auth_load_textdomain'
);

/**
 * Load plugin textdomain.
 *
 * @return void
 */
function webo_hmac_auth_load_textdomain() {
	load_plugin_textdomain(
		'webo-hmac-auth',
		false,
		dirname( plugin_basename( __FILE__ ) ) . '/languages'
	);
}

define( 'WEBO_HMAC_AUTH_VERSION', '1.0.0' );
define( 'WEBO_HMAC_AUTH_FILE', __FILE__ );
define( 'WEBO_HMAC_AUTH_PATH', plugin_dir_path( __FILE__ ) );

require_once WEBO_HMAC_AUTH_PATH . 'includes/class-activator.php';
require_once WEBO_HMAC_AUTH_PATH . 'includes/class-rate-limiter.php';
require_once WEBO_HMAC_AUTH_PATH . 'includes/class-scope-checker.php';
require_once WEBO_HMAC_AUTH_PATH . 'includes/class-key-manager.php';
require_once WEBO_HMAC_AUTH_PATH . 'includes/class-auth-middleware.php';
require_once WEBO_HMAC_AUTH_PATH . 'includes/class-admin-ui.php';

register_activation_hook(WEBO_HMAC_AUTH_FILE, ['WeboHmacAuth\\Activator', 'activate']);
register_deactivation_hook(WEBO_HMAC_AUTH_FILE, function () {
    $timestamp = wp_next_scheduled('webo_hmac_auth_cleanup_revoked_keys');
    if ($timestamp) {
        wp_unschedule_event($timestamp, 'webo_hmac_auth_cleanup_revoked_keys');
    }
});

add_action('plugins_loaded', function() {
    $key_manager = new WeboHmacAuth\KeyManager();

    if (!wp_next_scheduled('webo_hmac_auth_cleanup_revoked_keys')) {
        wp_schedule_event(time() + HOUR_IN_SECONDS, 'daily', 'webo_hmac_auth_cleanup_revoked_keys');
    }

    add_action('webo_hmac_auth_cleanup_revoked_keys', function () use ($key_manager) {
        $retention_days = (int) apply_filters('webo_hmac_auth_revoked_retention_days', 30);
        $key_manager->cleanup_revoked_clients(max(1, $retention_days));
    });

    $middleware = new WeboHmacAuth\AuthMiddleware(
        $key_manager,
        new WeboHmacAuth\RateLimiter(),
        new WeboHmacAuth\ScopeChecker()
    );
    $middleware->register();

    $admin_ui = new WeboHmacAuth\AdminUi($key_manager);
    $admin_ui->register();
});

add_filter('webo_hmac_auth_current_client', function($client) {
    if (is_array($client)) {
        return $client;
    }

    if (isset($GLOBALS['webo_hmac_auth_current_client']) && is_array($GLOBALS['webo_hmac_auth_current_client'])) {
        return $GLOBALS['webo_hmac_auth_current_client'];
    }

    return null;
});

/**
 * Ký request gửi đi (outbound HMAC). Plugin khác gọi khi cần gửi request có chữ ký WEBO HMAC.
 *
 * @param string      $method   HTTP method (GET, POST, ...).
 * @param string      $path     URL path dùng trong base string (vd: /webhook/xxx/chat).
 * @param string      $raw_body Raw body (POST); GET thì ''.
 * @param string|null $key_id   Key ID; null thì lấy từ user meta webo_hmac_key_id của user hiện tại.
 * @return array|null Headers ['X-WEBO-KEY' => ..., 'X-WEBO-TS' => ..., 'X-WEBO-SIGN' => ...] hoặc null.
 */
function webo_hmac_sign_request($method, $path, $raw_body = '', $key_id = null) {
    if ($key_id === null || $key_id === '') {
        $key_id = webo_hmac_get_key_id_for_user(get_current_user_id());
    }
    if (empty($key_id) || !is_string($key_id)) {
        return null;
    }
    $key_manager = new \WeboHmacAuth\KeyManager();
    return $key_manager->sign_outbound_request($key_id, $method, $path, $raw_body);
}

/**
 * Lấy key_id HMAC cho user (để ký request / authorKey). Ưu tiên user meta, không có thì lấy key active đầu tiên trong bảng.
 *
 * @param int|null $user_id User ID; null = user hiện tại.
 * @return string Key ID hoặc rỗng nếu không có.
 */
function webo_hmac_get_key_id_for_user($user_id = null) {
    if ($user_id === null) {
        $user_id = get_current_user_id();
    }
    if (!$user_id) {
        return '';
    }
    $key_id = get_user_meta($user_id, 'webo_hmac_key_id', true);
    if (!empty($key_id) && is_string($key_id)) {
        return $key_id;
    }
    $key_manager = new \WeboHmacAuth\KeyManager();
    $clients = $key_manager->list_clients_by_user((int) $user_id);
    foreach ($clients as $c) {
        if (isset($c['status']) && $c['status'] === 'active' && !empty($c['key_id'])) {
            return (string) $c['key_id'];
        }
    }
    return '';
}
