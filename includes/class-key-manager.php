<?php

namespace WeboHmacAuth;

use WP_Error;

if (!defined('ABSPATH')) {
    exit;
}

class KeyManager {
    /**
     * Return multisite-wide API clients table name.
     *
     * @return string
     */
    public function get_table_name() {
        global $wpdb;
        return $wpdb->base_prefix . 'webo_api_clients';
    }

    /**
     * List all clients with mapped user login.
     *
     * @return array
     */
    public function list_clients() {
        global $wpdb;

        $table = $this->get_table_name();
        $users_table = $wpdb->users;

        $sql = "SELECT c.*, u.user_login
            FROM {$table} c
            LEFT JOIN {$users_table} u ON u.ID = c.wp_user_id
            ORDER BY c.id DESC";

        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
        $rows = $wpdb->get_results($sql, ARRAY_A);

        return is_array($rows) ? $rows : [];
    }

    /**
     * List clients mapped to a specific WordPress user.
     *
     * @param int $wp_user_id WordPress user id.
     *
     * @return array
     */
    public function list_clients_by_user($wp_user_id) {
        global $wpdb;

        $table = $this->get_table_name();
        $users_table = $wpdb->users;

        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT c.*, u.user_login
                FROM {$table} c
                LEFT JOIN {$users_table} u ON u.ID = c.wp_user_id
                WHERE c.wp_user_id = %d
                ORDER BY c.id DESC",
                (int) $wp_user_id
            ),
            ARRAY_A
        );

        return is_array($rows) ? $rows : [];
    }

    /**
     * Create a new API client and return one-time plaintext secret.
     *
     * @param array $data Form data.
     *
     * @return array|WP_Error
     */
    public function create_client($data) {
        global $wpdb;

        $wp_user_id = isset($data['wp_user_id']) ? (int) $data['wp_user_id'] : 0;
        $rate_limit = isset($data['rate_limit']) ? max(1, (int) $data['rate_limit']) : 60;

        if ($wp_user_id <= 0 || !get_user_by('id', $wp_user_id)) {
            return new WP_Error('webo_invalid_user', 'Invalid WordPress user selected.');
        }

        $allowlist = $this->normalize_json_array(isset($data['allowlist']) ? $data['allowlist'] : '');
        if (is_wp_error($allowlist)) {
            return $allowlist;
        }

        $denylist = $this->normalize_json_array(isset($data['denylist']) ? $data['denylist'] : '');
        if (is_wp_error($denylist)) {
            return $denylist;
        }

        $allowed_sites = $this->normalize_sites(isset($data['allowed_sites']) ? $data['allowed_sites'] : '');
        if (is_wp_error($allowed_sites)) {
            return $allowed_sites;
        }

        $key_id = $this->generate_key_id();
        $secret = $this->generate_secret();

        $encrypted_secret = $this->encrypt_secret($secret);
        if (!$encrypted_secret) {
            return new WP_Error('webo_encrypt_failed', 'Could not securely store secret. Ensure OpenSSL is available.');
        }

        $inserted = $wpdb->insert(
            $this->get_table_name(),
            [
                'key_id'       => $key_id,
                'secret_hash'  => password_hash($secret, PASSWORD_DEFAULT),
                'wp_user_id'   => $wp_user_id,
                'allowed_sites'=> !empty($allowed_sites) ? wp_json_encode($allowed_sites) : null,
                'allowlist'    => !empty($allowlist) ? wp_json_encode($allowlist) : null,
                'denylist'     => !empty($denylist) ? wp_json_encode($denylist) : null,
                'rate_limit'   => $rate_limit,
                'status'       => 'active',
                'created_at'   => current_time('mysql'),
            ],
            [
                '%s', '%s', '%d', '%s', '%s', '%s', '%d', '%s', '%s',
            ]
        );

        if (false === $inserted) {
            return new WP_Error('webo_insert_failed', 'Failed to create API client.');
        }

        $this->store_encrypted_secret($key_id, $encrypted_secret);

        return [
            'id'     => (int) $wpdb->insert_id,
            'key_id' => $key_id,
            'secret' => $secret,
        ];
    }

    /**
     * Revoke key by changing status to revoked.
     *
     * @param int $id Row id.
     *
     * @return bool
     */
    public function revoke_client($id) {
        global $wpdb;

        $updated = $wpdb->update(
            $this->get_table_name(),
            ['status' => 'revoked'],
            ['id' => (int) $id],
            ['%s'],
            ['%d']
        );

        return false !== $updated;
    }

    /**
     * Rotate secret for an existing key and return one-time new secret.
     *
     * @param int $id Row id.
     *
     * @return array|WP_Error
     */
    public function rotate_secret($id) {
        global $wpdb;

        $row = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT id, key_id FROM {$this->get_table_name()} WHERE id = %d",
                (int) $id
            ),
            ARRAY_A
        );

        if (!$row) {
            return new WP_Error('webo_not_found', 'API key not found.');
        }

        $secret = $this->generate_secret();
        $encrypted_secret = $this->encrypt_secret($secret);
        if (!$encrypted_secret) {
            return new WP_Error('webo_encrypt_failed', 'Could not securely store secret. Ensure OpenSSL is available.');
        }

        $updated = $wpdb->update(
            $this->get_table_name(),
            ['secret_hash' => password_hash($secret, PASSWORD_DEFAULT)],
            ['id' => (int) $row['id']],
            ['%s'],
            ['%d']
        );

        if (false === $updated) {
            return new WP_Error('webo_rotate_failed', 'Failed to rotate secret.');
        }

        $this->store_encrypted_secret($row['key_id'], $encrypted_secret);

        return [
            'key_id' => $row['key_id'],
            'secret' => $secret,
        ];
    }

    /**
     * Rotate secret for key owned by specific user.
     *
     * @param int $id         Key row id.
     * @param int $wp_user_id Owner user id.
     *
     * @return array|WP_Error
     */
    public function rotate_secret_for_user($id, $wp_user_id) {
        global $wpdb;

        $row = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT id, key_id, status, wp_user_id FROM {$this->get_table_name()} WHERE id = %d LIMIT 1",
                (int) $id
            ),
            ARRAY_A
        );

        if (!$row) {
            return new WP_Error('webo_not_found', 'API key not found.');
        }

        if ((int) $row['wp_user_id'] !== (int) $wp_user_id) {
            return new WP_Error('webo_forbidden', 'You can only rotate your own API keys.');
        }

        if ('active' !== (string) $row['status']) {
            return new WP_Error('webo_inactive_key', 'Only active API keys can be rotated.');
        }

        return $this->rotate_secret((int) $row['id']);
    }

    /**
     * Find client row by key id.
     *
     * @param string $key_id API key id.
     *
     * @return array|null
     */
    public function get_client_by_key_id($key_id) {
        global $wpdb;

        $key_id = sanitize_text_field($key_id);
        if ('' === $key_id) {
            return null;
        }

        $row = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT * FROM {$this->get_table_name()} WHERE key_id = %s LIMIT 1",
                $key_id
            ),
            ARRAY_A
        );

        return is_array($row) ? $row : null;
    }

    /**
     * Validate HMAC signature.
     *
     * @param array  $client    Client row.
     * @param string $method    HTTP method.
     * @param string $path      URL path.
     * @param string $timestamp Timestamp header.
     * @param string $raw_body  Raw request body.
     * @param string $signature Provided signature.
     *
     * @return bool
     */
    public function verify_signature($client, $method, $path, $timestamp, $raw_body, $signature) {
        $secret = $this->get_plain_secret_for_key($client['key_id']);
        if (!$secret) {
            return false;
        }

        $body_hash = hash('sha256', (string) $raw_body);
        $base_string = strtoupper((string) $method) . "\n" . (string) $path . "\n" . (string) $timestamp . "\n" . $body_hash;

        // Use base64 signature transport by default.
        $expected = base64_encode(hash_hmac('sha256', $base_string, $secret, true));

        return hash_equals($expected, (string) $signature);
    }

    /**
     * Update last usage timestamp.
     *
     * @param string $key_id API key id.
     */
    public function update_last_used($key_id) {
        global $wpdb;

        $wpdb->update(
            $this->get_table_name(),
            ['last_used_at' => current_time('mysql')],
            ['key_id' => sanitize_text_field($key_id)],
            ['%s'],
            ['%s']
        );
    }

    /**
     * Normalize allowlist/denylist JSON into string array.
     *
     * @param string $json_raw Raw JSON input.
     *
     * @return array|WP_Error
     */
    public function normalize_json_array($json_raw) {
        $json_raw = trim((string) $json_raw);

        if ('' === $json_raw) {
            return [];
        }

        $decoded = json_decode($json_raw, true);
        if (!is_array($decoded)) {
            return new WP_Error('webo_invalid_json', 'Allowlist/Denylist must be valid JSON array.');
        }

        $normalized = [];
        foreach ($decoded as $item) {
            if (!is_scalar($item)) {
                return new WP_Error('webo_invalid_json_item', 'Allowlist/Denylist items must be scalar values.');
            }

            $value = sanitize_text_field((string) $item);
            if ('' !== $value) {
                $normalized[] = $value;
            }
        }

        return array_values(array_unique($normalized));
    }

    /**
     * Normalize comma-separated site IDs.
     *
     * @param string $raw Comma-separated ids.
     *
     * @return array|WP_Error
     */
    public function normalize_sites($raw) {
        $raw = trim((string) $raw);
        if ('' === $raw) {
            return [];
        }

        $parts = array_map('trim', explode(',', $raw));
        $sites = [];

        foreach ($parts as $part) {
            if ('' === $part) {
                continue;
            }

            if (!ctype_digit($part)) {
                return new WP_Error('webo_invalid_site_id', 'Allowed sites must be comma-separated numeric blog IDs.');
            }

            $sites[] = (int) $part;
        }

        return array_values(array_unique($sites));
    }

    /**
     * Generate stable key identifier.
     *
     * @return string
     */
    private function generate_key_id() {
        return 'wk_' . bin2hex(random_bytes(16));
    }

    /**
     * Generate one-time plaintext secret.
     *
     * @return string
     */
    private function generate_secret() {
        return $this->base64url_encode(random_bytes(32));
    }

    /**
     * Encode binary to URL-safe base64 (without padding).
     *
     * @param string $binary Binary data.
     *
     * @return string
     */
    private function base64url_encode($binary) {
        return rtrim(strtr(base64_encode($binary), '+/', '-_'), '=');
    }

    /**
     * Store encrypted secret in network option.
     *
     * @param string $key_id            API key id.
     * @param string $encrypted_payload Encrypted secret payload.
     */
    private function store_encrypted_secret($key_id, $encrypted_payload) {
        $store = get_site_option('webo_hmac_auth_secret_store', []);
        if (!is_array($store)) {
            $store = [];
        }

        $store[$key_id] = $encrypted_payload;
        update_site_option('webo_hmac_auth_secret_store', $store);
    }

    /**
     * Retrieve plaintext secret by key id.
     *
     * @param string $key_id API key id.
     *
     * @return string|false
     */
    private function get_plain_secret_for_key($key_id) {
        $store = get_site_option('webo_hmac_auth_secret_store', []);
        if (!is_array($store) || empty($store[$key_id])) {
            return false;
        }

        return $this->decrypt_secret($store[$key_id]);
    }

    /**
     * Encrypt secret with OpenSSL + HMAC for at-rest protection.
     *
     * @param string $secret Plaintext secret.
     *
     * @return string|false
     */
    private function encrypt_secret($secret) {
        if (!function_exists('openssl_encrypt')) {
            return false;
        }

        $key = $this->get_encryption_key();
        $cipher = 'AES-256-CBC';
        $iv_length = openssl_cipher_iv_length($cipher);

        if ($iv_length <= 0) {
            return false;
        }

        $iv = random_bytes($iv_length);
        $ciphertext = openssl_encrypt($secret, $cipher, $key, OPENSSL_RAW_DATA, $iv);

        if (false === $ciphertext) {
            return false;
        }

        $mac = hash_hmac('sha256', $iv . $ciphertext, $key, true);

        return base64_encode($iv . $mac . $ciphertext);
    }

    /**
     * Decrypt secret with MAC verification.
     *
     * @param string $payload Encoded payload.
     *
     * @return string|false
     */
    private function decrypt_secret($payload) {
        if (!function_exists('openssl_decrypt')) {
            return false;
        }

        $decoded = base64_decode($payload, true);
        if (false === $decoded) {
            return false;
        }

        $key = $this->get_encryption_key();
        $cipher = 'AES-256-CBC';
        $iv_length = openssl_cipher_iv_length($cipher);
        $mac_length = 32;

        if (strlen($decoded) <= ($iv_length + $mac_length)) {
            return false;
        }

        $iv = substr($decoded, 0, $iv_length);
        $mac = substr($decoded, $iv_length, $mac_length);
        $ciphertext = substr($decoded, $iv_length + $mac_length);

        $calc_mac = hash_hmac('sha256', $iv . $ciphertext, $key, true);
        if (!hash_equals($mac, $calc_mac)) {
            return false;
        }

        return openssl_decrypt($ciphertext, $cipher, $key, OPENSSL_RAW_DATA, $iv);
    }

    /**
     * Build encryption key from WordPress salts.
     *
     * @return string
     */
    private function get_encryption_key() {
        $material = AUTH_KEY . SECURE_AUTH_KEY . LOGGED_IN_KEY . NONCE_KEY;
        return hash('sha256', $material, true);
    }
}
