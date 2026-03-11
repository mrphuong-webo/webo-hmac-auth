<?php

namespace WeboHmacAuth;

use WP_Error;

if (!defined('ABSPATH')) {
    exit;
}

class KeyManager {
    /** @var bool */
    private $key_name_column_checked = false;
    /** @var bool */
    private $revoked_at_column_checked = false;

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

        $this->ensure_key_name_column();

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

        $this->ensure_key_name_column();

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

        $this->ensure_key_name_column();

        $wp_user_id = isset($data['wp_user_id']) ? (int) $data['wp_user_id'] : 0;
        $key_name = isset($data['key_name']) ? sanitize_text_field((string) $data['key_name']) : '';
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
                'key_name'     => '' !== $key_name ? $key_name : null,
                'allowed_sites'=> !empty($allowed_sites) ? wp_json_encode($allowed_sites) : null,
                'allowlist'    => !empty($allowlist) ? wp_json_encode($allowlist) : null,
                'denylist'     => !empty($denylist) ? wp_json_encode($denylist) : null,
                'rate_limit'   => $rate_limit,
                'status'       => 'active',
                'created_at'   => current_time('mysql'),
            ],
            [
                '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%d', '%s', '%s',
            ]
        );

        if (false === $inserted) {
            return new WP_Error('webo_insert_failed', 'Failed to create API client.');
        }

        update_user_meta($wp_user_id, 'webo_hmac_key_id', $key_id);

        $this->store_encrypted_secret($key_id, $encrypted_secret);

        return [
            'id'         => (int) $wpdb->insert_id,
            'key_id'     => $key_id,
            'secret'     => $secret,
            'key_name'   => $key_name,
            'rate_limit' => $rate_limit,
            'status'     => 'active',
            'last_used_at' => '-',
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

        $this->ensure_revoked_at_column();

        $updated = $wpdb->update(
            $this->get_table_name(),
            [
                'status' => 'revoked',
                'revoked_at' => current_time('mysql'),
            ],
            ['id' => (int) $id],
            ['%s', '%s'],
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
     * Sign an outbound request (e.g. từ WordPress gửi sang n8n). Dùng cho plugin client gọi HMAC.
     *
     * @param string $key_id   API key id (của user hiện tại hoặc truyền vào).
     * @param string $method   HTTP method (GET, POST, ...).
     * @param string $path     URL path dùng trong base string (vd: /webhook/xxx/chat).
     * @param string $raw_body Raw body để hash (GET thì '').
     *
     * @return array|null Headers ['X-WEBO-KEY' => ..., 'X-WEBO-TS' => ..., 'X-WEBO-SIGN' => ...] hoặc null nếu không ký được.
     */
    public function sign_outbound_request($key_id, $method, $path, $raw_body = '') {
        $key_id = is_string($key_id) ? trim($key_id) : '';
        if ($key_id === '') {
            return null;
        }
        $secret = $this->get_plain_secret_for_key($key_id);
        if (!$secret) {
            return null;
        }
        $ts = (string) time();
        $body_hash = hash('sha256', (string) $raw_body);
        $base_string = strtoupper((string) $method) . "\n" . (string) $path . "\n" . $ts . "\n" . $body_hash;
        $sign = base64_encode(hash_hmac('sha256', $base_string, $secret, true));
        return [
            'X-WEBO-KEY' => $key_id,
            'X-WEBO-TS'  => $ts,
            'X-WEBO-SIGN'=> $sign,
        ];
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
     * Create portal-connect client with configurable status.
     *
     * @param array $data Client creation payload.
     *
     * @return array|WP_Error
     */
    public function create_portal_client($data) {
        global $wpdb;

        $this->ensure_key_name_column();

        $wp_user_id = isset($data['wp_user_id']) ? (int) $data['wp_user_id'] : 0;
        $key_name   = isset($data['key_name']) ? sanitize_text_field((string) $data['key_name']) : '';
        $rate_limit = isset($data['rate_limit']) ? max(1, (int) $data['rate_limit']) : 60;
        $status     = isset($data['status']) ? sanitize_key((string) $data['status']) : 'pending';

        if (!in_array($status, ['pending', 'active', 'revoked'], true)) {
            $status = 'pending';
        }

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

        $key_id = $this->generate_portal_key_id();
        $secret = $this->generate_portal_secret();

        $encrypted_secret = $this->encrypt_secret($secret);
        if (!$encrypted_secret) {
            return new WP_Error('webo_encrypt_failed', 'Could not securely store secret. Ensure OpenSSL is available.');
        }

        $inserted = $wpdb->insert(
            $this->get_table_name(),
            [
                'key_id'        => $key_id,
                'secret_hash'   => password_hash($secret, PASSWORD_DEFAULT),
                'wp_user_id'    => $wp_user_id,
                'key_name'      => '' !== $key_name ? $key_name : null,
                'allowed_sites' => !empty($allowed_sites) ? wp_json_encode($allowed_sites) : null,
                'allowlist'     => !empty($allowlist) ? wp_json_encode($allowlist) : null,
                'denylist'      => !empty($denylist) ? wp_json_encode($denylist) : null,
                'rate_limit'    => $rate_limit,
                'status'        => $status,
                'created_at'    => current_time('mysql'),
            ],
            [
                '%s', '%s', '%d', '%s', '%s', '%s', '%s', '%d', '%s', '%s',
            ]
        );

        if (false === $inserted) {
            return new WP_Error('webo_insert_failed', 'Failed to create API client.');
        }

        $this->store_encrypted_secret($key_id, $encrypted_secret);

        return [
            'id'         => (int) $wpdb->insert_id,
            'key_id'     => $key_id,
            'secret'     => $secret,
            'key_name'   => $key_name,
            'rate_limit' => $rate_limit,
            'status'     => $status,
            'last_used_at' => '-',
            'user_id'    => $wp_user_id,
        ];
    }

    /**
     * Ensure key_name column exists for upgraded sites.
     */
    private function ensure_key_name_column() {
        global $wpdb;

        if ($this->key_name_column_checked) {
            return;
        }

        $this->key_name_column_checked = true;

        $table = $this->get_table_name();
        $column = $wpdb->get_var(
            $wpdb->prepare(
                "SHOW COLUMNS FROM {$table} LIKE %s",
                'key_name'
            )
        );

        if (null !== $column) {
            return;
        }

        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
        $wpdb->query("ALTER TABLE {$table} ADD COLUMN key_name VARCHAR(191) NULL AFTER wp_user_id");
    }

    /**
     * Ensure revoked_at column exists for retention cleanup.
     */
    private function ensure_revoked_at_column() {
        global $wpdb;

        if ($this->revoked_at_column_checked) {
            return;
        }

        $this->revoked_at_column_checked = true;

        $table = $this->get_table_name();
        $column = $wpdb->get_var(
            $wpdb->prepare(
                "SHOW COLUMNS FROM {$table} LIKE %s",
                'revoked_at'
            )
        );

        if (null !== $column) {
            return;
        }

        // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
        $wpdb->query("ALTER TABLE {$table} ADD COLUMN revoked_at DATETIME NULL AFTER status");
    }

    /**
     * Set key status by key id.
     *
     * @param string $key_id Key ID.
     * @param string $status Target status.
     *
     * @return bool
     */
    public function set_client_status_by_key_id($key_id, $status) {
        global $wpdb;

        $this->ensure_revoked_at_column();

        $key_id = sanitize_text_field((string) $key_id);
        $status = sanitize_key((string) $status);
        if ('' === $key_id || !in_array($status, ['pending', 'active', 'revoked'], true)) {
            return false;
        }

        $update_data = ['status' => $status];
        $update_format = ['%s'];

        if ('revoked' === $status) {
            $update_data['revoked_at'] = current_time('mysql');
            $update_format[] = '%s';
        } else {
            $update_data['revoked_at'] = null;
            $update_format[] = '%s';
        }

        $updated = $wpdb->update(
            $this->get_table_name(),
            $update_data,
            ['key_id' => $key_id],
            $update_format,
            ['%s']
        );

        return false !== $updated;
    }

    /**
     * Delete revoked keys older than retention period.
     *
     * @param int $days Retention days.
     *
     * @return int Number of deleted keys.
     */
    public function cleanup_revoked_clients($days = 30) {
        global $wpdb;

        $this->ensure_revoked_at_column();

        $days = max(1, (int) $days);
        $cutoff = gmdate('Y-m-d H:i:s', time() - (DAY_IN_SECONDS * $days));
        $table = $this->get_table_name();

        $rows = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT key_id FROM {$table}
                WHERE status = %s
                  AND (
                    (revoked_at IS NOT NULL AND revoked_at <= %s)
                    OR (revoked_at IS NULL AND created_at <= %s)
                  )",
                'revoked',
                $cutoff,
                $cutoff
            ),
            ARRAY_A
        );

        if (!is_array($rows) || empty($rows)) {
            return 0;
        }

        $deleted_count = 0;
        $store = get_site_option('webo_hmac_auth_secret_store', []);
        if (!is_array($store)) {
            $store = [];
        }

        foreach ($rows as $row) {
            $key_id = isset($row['key_id']) ? sanitize_text_field((string) $row['key_id']) : '';
            if ('' === $key_id) {
                continue;
            }

            $deleted = $wpdb->delete(
                $table,
                ['key_id' => $key_id],
                ['%s']
            );

            if (false !== $deleted) {
                $deleted_count += (int) $deleted;
                if (isset($store[$key_id])) {
                    unset($store[$key_id]);
                }
            }
        }

        update_site_option('webo_hmac_auth_secret_store', $store);

        return $deleted_count;
    }

    /**
     * Delete key by key id.
     *
     * @param string $key_id Key ID.
     *
     * @return bool
     */
    public function delete_client_by_key_id($key_id) {
        global $wpdb;

        $key_id = sanitize_text_field((string) $key_id);
        if ('' === $key_id) {
            return false;
        }

        $deleted = $wpdb->delete(
            $this->get_table_name(),
            ['key_id' => $key_id],
            ['%s']
        );

        $store = get_site_option('webo_hmac_auth_secret_store', []);
        if (is_array($store) && isset($store[$key_id])) {
            unset($store[$key_id]);
            update_site_option('webo_hmac_auth_secret_store', $store);
        }

        return false !== $deleted;
    }

    /**
     * Delete key by row id.
     *
     * @param int $id Row id.
     *
     * @return bool
     */
    public function delete_client_by_id($id) {
        global $wpdb;

        $row = $wpdb->get_row(
            $wpdb->prepare(
                "SELECT key_id FROM {$this->get_table_name()} WHERE id = %d LIMIT 1",
                (int) $id
            ),
            ARRAY_A
        );

        if (!is_array($row) || empty($row['key_id'])) {
            return false;
        }

        return $this->delete_client_by_key_id((string) $row['key_id']);
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
     * Generate portal key id in required format.
     *
     * @return string
     */
    private function generate_portal_key_id() {
        return 'webo_' . substr(strtolower(bin2hex(random_bytes(16))), 0, 16);
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
     * Generate portal secret in required length.
     *
     * @return string
     */
    private function generate_portal_secret() {
        return $this->base64url_encode(random_bytes(48));
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
