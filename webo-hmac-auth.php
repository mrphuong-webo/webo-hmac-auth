<?php
/**
 * Plugin Name: WEBO HMAC Auth
 * Description: HMAC authentication middleware for WEBO MCP and WP Abilities endpoints (multisite-ready, network admin managed API keys).
 * Version: 1.0.0
 * Author: WEBO
 * Text Domain: webo-hmac-auth
 * Requires at least: 6.0
 * Requires PHP: 7.4
 * Network: true
 *
 * Network activation notes:
 * - Activate from Network Admin > Plugins.
 * - API key management UI is available only in Network Admin.
 * - Database table uses $wpdb->base_prefix for multisite-wide key storage.
 */

if (!defined('ABSPATH')) {
    exit;
}

define('WEBO_HMAC_AUTH_VERSION', '1.0.0');
define('WEBO_HMAC_AUTH_FILE', __FILE__);
define('WEBO_HMAC_AUTH_PATH', plugin_dir_path(__FILE__));

require_once WEBO_HMAC_AUTH_PATH . 'includes/class-activator.php';
require_once WEBO_HMAC_AUTH_PATH . 'includes/class-rate-limiter.php';
require_once WEBO_HMAC_AUTH_PATH . 'includes/class-scope-checker.php';
require_once WEBO_HMAC_AUTH_PATH . 'includes/class-key-manager.php';
require_once WEBO_HMAC_AUTH_PATH . 'includes/class-auth-middleware.php';
require_once WEBO_HMAC_AUTH_PATH . 'includes/class-admin-ui.php';

register_activation_hook(WEBO_HMAC_AUTH_FILE, ['WeboHmacAuth\\Activator', 'activate']);

add_action('plugins_loaded', function() {
    $key_manager = new WeboHmacAuth\KeyManager();

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
