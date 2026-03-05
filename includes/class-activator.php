<?php

namespace WeboHmacAuth;

if (!defined('ABSPATH')) {
    exit;
}

class Activator {
    /**
     * Create multisite-wide table for API clients.
     *
     * @param bool $network_wide Whether activation is network-wide.
     */
    public static function activate($network_wide) {
        global $wpdb;

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';

        $table_name = $wpdb->base_prefix . 'webo_api_clients';
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE {$table_name} (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            key_id VARCHAR(64) NOT NULL,
            secret_hash VARCHAR(255) NOT NULL,
            wp_user_id BIGINT UNSIGNED NOT NULL,
            key_name VARCHAR(191) NULL,
            allowed_sites LONGTEXT NULL,
            allowlist LONGTEXT NULL,
            denylist LONGTEXT NULL,
            rate_limit INT NOT NULL DEFAULT 60,
            status VARCHAR(20) NOT NULL DEFAULT 'active',
            revoked_at DATETIME NULL,
            last_used_at DATETIME NULL,
            created_at DATETIME NOT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY key_id (key_id),
            KEY wp_user_id (wp_user_id)
        ) {$charset_collate};";

        dbDelta($sql);

        // Store schema version for future migrations.
        update_site_option('webo_hmac_auth_db_version', '1.1.0');
    }
}
