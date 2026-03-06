<?php
/**
 * Plugin Name: WEBO HMAC Auth
 * Description: HMAC authentication middleware for WEBO WordPress MCP and WP Abilities endpoints (multisite-ready, network admin managed API keys).
 * Version: 1.0.0
 * Author: WEBO
 * Text Domain: webo-hmac-auth
 * Requires at least: 6.0
 * Requires PHP: 7.4
 * Requires Plugins: webo-wordpress-mcp
 * Network: false
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
