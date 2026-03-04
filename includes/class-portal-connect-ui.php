<?php

namespace WeboHmacAuth;

use WP_Error;

if (!defined('ABSPATH')) {
    exit;
}

class PortalConnectUi {
    /** @var KeyManager */
    private $key_manager;

    public function __construct(KeyManager $key_manager) {
        $this->key_manager = $key_manager;
    }

    public function register() {
        add_action('admin_menu', [$this, 'register_admin_menu']);
        add_action('network_admin_menu', [$this, 'register_network_menu']);
        add_action('admin_post_webo_hmac_connect_trolywp', [$this, 'handle_connect']);
    }

    public function register_admin_menu() {
        if (is_multisite()) {
            return;
        }

        add_options_page(
            'Connect TrolyWP',
            'Connect TrolyWP',
            'manage_options',
            'webo-hmac-connect-trolywp',
            [$this, 'render_page']
        );
    }

    public function register_network_menu() {
        add_submenu_page(
            'settings.php',
            'Connect TrolyWP',
            'Connect TrolyWP',
            'manage_network_options',
            'webo-hmac-connect-trolywp',
            [$this, 'render_page']
        );
    }

    public function render_page() {
        if (!$this->current_user_can_manage()) {
            wp_die(esc_html__('You do not have permission to access this page.', 'webo-hmac-auth'));
        }

        $state = $this->get_portal_state();
        $portal_url = isset($state['portal_url']) ? (string) $state['portal_url'] : 'https://trolywp.ai';
        $rollback_on_fail = !empty($state['rollback_on_fail']);
        $mapped_user_mode = isset($state['mapped_user_mode']) ? (string) $state['mapped_user_mode'] : 'webo_agent';

        $status_message = isset($_GET['message']) ? sanitize_text_field(wp_unslash($_GET['message'])) : '';
        $status_type = isset($_GET['type']) ? sanitize_key(wp_unslash($_GET['type'])) : 'success';
        ?>
        <div class="wrap">
            <h1><?php echo esc_html__('Connect TrolyWP', 'webo-hmac-auth'); ?></h1>

            <?php if ('' !== $status_message) : ?>
                <div class="notice <?php echo ('error' === $status_type) ? 'notice-error' : 'notice-success'; ?> is-dismissible">
                    <p><?php echo esc_html(rawurldecode($status_message)); ?></p>
                </div>
            <?php endif; ?>

            <table class="widefat striped" style="max-width:960px;margin-bottom:20px;">
                <tbody>
                <tr>
                    <th style="width:220px;"><?php echo esc_html__('Status', 'webo-hmac-auth'); ?></th>
                    <td><strong><?php echo esc_html(isset($state['status']) ? (string) $state['status'] : 'disconnected'); ?></strong></td>
                </tr>
                <tr>
                    <th><?php echo esc_html__('Portal URL', 'webo-hmac-auth'); ?></th>
                    <td><?php echo esc_html($portal_url); ?></td>
                </tr>
                <tr>
                    <th><?php echo esc_html__('Portal Site ID', 'webo-hmac-auth'); ?></th>
                    <td><?php echo esc_html(isset($state['portal_site_id']) ? (string) $state['portal_site_id'] : '-'); ?></td>
                </tr>
                <tr>
                    <th><?php echo esc_html__('Key ID', 'webo-hmac-auth'); ?></th>
                    <td><code><?php echo esc_html(isset($state['key_id']) ? (string) $state['key_id'] : '-'); ?></code></td>
                </tr>
                <tr>
                    <th><?php echo esc_html__('Last Attempt', 'webo-hmac-auth'); ?></th>
                    <td><?php echo esc_html(isset($state['last_attempt_at']) ? (string) $state['last_attempt_at'] : '-'); ?></td>
                </tr>
                <tr>
                    <th><?php echo esc_html__('Last Error', 'webo-hmac-auth'); ?></th>
                    <td><?php echo esc_html(isset($state['last_error']) ? (string) $state['last_error'] : '-'); ?></td>
                </tr>
                </tbody>
            </table>

            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <input type="hidden" name="action" value="webo_hmac_connect_trolywp" />
                <?php wp_nonce_field('webo_hmac_connect_trolywp'); ?>

                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><label for="portal_url"><?php echo esc_html__('Portal URL', 'webo-hmac-auth'); ?></label></th>
                        <td>
                            <input id="portal_url" name="portal_url" type="url" class="regular-text" value="<?php echo esc_attr($portal_url); ?>" required />
                            <p class="description"><?php echo esc_html__('Default: https://trolywp.ai', 'webo-hmac-auth'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="install_token"><?php echo esc_html__('Install Token', 'webo-hmac-auth'); ?></label></th>
                        <td>
                            <input id="install_token" name="install_token" type="text" class="regular-text" required />
                            <p class="description"><?php echo esc_html__('One-time token from portal (TTL 15 minutes).', 'webo-hmac-auth'); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="mapped_user_mode"><?php echo esc_html__('Mapped WP User', 'webo-hmac-auth'); ?></label></th>
                        <td>
                            <select id="mapped_user_mode" name="mapped_user_mode">
                                <option value="webo_agent" <?php selected($mapped_user_mode, 'webo_agent'); ?>><?php echo esc_html__('Dedicated webo_agent user', 'webo-hmac-auth'); ?></option>
                                <option value="current_admin" <?php selected($mapped_user_mode, 'current_admin'); ?>><?php echo esc_html__('Current admin user', 'webo-hmac-auth'); ?></option>
                            </select>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php echo esc_html__('On Failure', 'webo-hmac-auth'); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" name="rollback_on_fail" value="1" <?php checked($rollback_on_fail); ?> />
                                <?php echo esc_html__('Rollback created pending key when connect fails', 'webo-hmac-auth'); ?>
                            </label>
                        </td>
                    </tr>
                </table>

                <?php submit_button(__('Connect / Retry', 'webo-hmac-auth')); ?>
            </form>
        </div>
        <?php
    }

    public function handle_connect() {
        if (!$this->current_user_can_manage()) {
            wp_die(esc_html__('You are not allowed to do this.', 'webo-hmac-auth'));
        }

        check_admin_referer('webo_hmac_connect_trolywp');

        $portal_url_raw = isset($_POST['portal_url']) ? (string) wp_unslash($_POST['portal_url']) : 'https://trolywp.ai';
        $install_token = isset($_POST['install_token']) ? sanitize_text_field((string) wp_unslash($_POST['install_token'])) : '';
        $rollback_on_fail = !empty($_POST['rollback_on_fail']);
        $mapped_user_mode = isset($_POST['mapped_user_mode']) ? sanitize_key((string) wp_unslash($_POST['mapped_user_mode'])) : 'webo_agent';

        $portal_url = $this->normalize_portal_url($portal_url_raw);
        if (is_wp_error($portal_url)) {
            $this->save_portal_state([
                'portal_url' => $portal_url_raw,
                'rollback_on_fail' => $rollback_on_fail,
                'mapped_user_mode' => $mapped_user_mode,
                'last_error' => $portal_url->get_error_message(),
                'last_attempt_at' => current_time('mysql'),
            ]);
            $this->redirect_with_message($portal_url->get_error_message(), true);
        }

        if ('' === $install_token) {
            $this->redirect_with_message('Install token is required.', true);
        }

        $mapped_user_id = $this->resolve_mapped_user_id($mapped_user_mode);
        if (is_wp_error($mapped_user_id)) {
            $this->redirect_with_message($mapped_user_id->get_error_message(), true);
        }

        $client = $this->key_manager->create_portal_client([
            'wp_user_id' => (int) $mapped_user_id,
            'rate_limit' => 60,
            'status' => 'pending',
            'allowlist' => '[]',
            'denylist' => '[]',
            'allowed_sites' => '',
        ]);

        if (is_wp_error($client)) {
            $this->redirect_with_message($client->get_error_message(), true);
        }

        $payload = [
            'install_token' => $install_token,
            'site_url' => untrailingslashit(home_url('/')),
            'key_id' => $client['key_id'],
            'secret' => $client['secret'],
            'scopes' => ['mcp', 'abilities'],
            'rate_limit' => 60,
            'client_meta' => [
                'webo_hmac_version' => defined('WEBO_HMAC_AUTH_VERSION') ? WEBO_HMAC_AUTH_VERSION : '',
                'webo_mcp_version' => $this->get_webo_mcp_version(),
            ],
        ];

        $response = wp_remote_post(
            untrailingslashit($portal_url) . '/wp-json/trolywp/v1/site/register',
            [
                'timeout' => 20,
                'headers' => [
                    'Content-Type' => 'application/json',
                ],
                'body' => wp_json_encode($payload),
            ]
        );

        if (is_wp_error($response)) {
            $this->handle_connect_failure($client['key_id'], $portal_url, $rollback_on_fail, $mapped_user_mode, $response->get_error_message());
        }

        $status_code = (int) wp_remote_retrieve_response_code($response);
        $body = wp_remote_retrieve_body($response);
        $decoded = json_decode((string) $body, true);

        if ($status_code >= 200 && $status_code < 300 && is_array($decoded) && !empty($decoded['ok']) && !empty($decoded['portal_site_id'])) {
            $previous_state = $this->get_portal_state();
            $previous_key_id = isset($previous_state['key_id']) ? sanitize_text_field((string) $previous_state['key_id']) : '';

            $this->key_manager->set_client_status_by_key_id($client['key_id'], 'active');

            if ('' !== $previous_key_id && $previous_key_id !== $client['key_id']) {
                $this->key_manager->set_client_status_by_key_id($previous_key_id, 'revoked');
            }

            $this->save_portal_state([
                'status' => 'connected',
                'portal_url' => $portal_url,
                'portal_site_id' => (int) $decoded['portal_site_id'],
                'key_id' => $client['key_id'],
                'rollback_on_fail' => $rollback_on_fail,
                'mapped_user_mode' => $mapped_user_mode,
                'last_error' => '',
                'last_attempt_at' => current_time('mysql'),
                'scopes' => ['mcp', 'abilities'],
                'rate_limit' => 60,
            ]);

            $this->redirect_with_message('Connected to TrolyWP portal successfully.', false);
        }

        $message = 'Portal registration failed.';
        if (is_array($decoded) && !empty($decoded['message'])) {
            $message = sanitize_text_field((string) $decoded['message']);
        }

        $this->handle_connect_failure($client['key_id'], $portal_url, $rollback_on_fail, $mapped_user_mode, $message);
    }

    private function handle_connect_failure($key_id, $portal_url, $rollback_on_fail, $mapped_user_mode, $error_message) {
        if ($rollback_on_fail) {
            $this->key_manager->delete_client_by_key_id($key_id);
        }

        $this->save_portal_state([
            'status' => 'pending',
            'portal_url' => $portal_url,
            'key_id' => $key_id,
            'rollback_on_fail' => (bool) $rollback_on_fail,
            'mapped_user_mode' => (string) $mapped_user_mode,
            'last_error' => (string) $error_message,
            'last_attempt_at' => current_time('mysql'),
        ]);

        $this->redirect_with_message((string) $error_message, true);
    }

    private function normalize_portal_url($url) {
        $url = trim((string) $url);
        if ('' === $url) {
            $url = 'https://trolywp.ai';
        }

        $url = esc_url_raw($url);
        if ('' === $url) {
            return new WP_Error('webo_invalid_portal_url', 'Portal URL is invalid.');
        }

        $parts = wp_parse_url($url);
        if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
            return new WP_Error('webo_invalid_portal_url', 'Portal URL is invalid.');
        }

        if ('https' !== strtolower((string) $parts['scheme'])) {
            return new WP_Error('webo_invalid_portal_url', 'Portal URL must use HTTPS.');
        }

        return untrailingslashit($parts['scheme'] . '://' . $parts['host'] . (isset($parts['port']) ? ':' . (int) $parts['port'] : ''));
    }

    private function resolve_mapped_user_id($mode) {
        if ('current_admin' === $mode) {
            $uid = get_current_user_id();
            if ($uid > 0) {
                return $uid;
            }

            return new WP_Error('webo_invalid_user', 'Current admin user could not be resolved.');
        }

        $existing = get_user_by('login', 'webo_agent');
        if ($existing && !empty($existing->ID)) {
            return (int) $existing->ID;
        }

        $email_host = wp_parse_url(home_url('/'), PHP_URL_HOST);
        if (!is_string($email_host) || '' === $email_host) {
            $email_host = 'example.com';
        }

        $email = 'webo_agent@' . preg_replace('/[^a-z0-9\.-]/i', '', $email_host);
        $password = wp_generate_password(24, true, true);

        $uid = wp_create_user('webo_agent', $password, $email);
        if (is_wp_error($uid)) {
            return $uid;
        }

        $uid = (int) $uid;
        if (is_multisite()) {
            add_user_to_blog(get_current_blog_id(), $uid, 'administrator');
        } else {
            $user = new \WP_User($uid);
            $user->set_role('administrator');
        }

        return $uid;
    }

    private function current_user_can_manage() {
        return is_multisite() ? current_user_can('manage_network_options') : current_user_can('manage_options');
    }

    private function redirect_with_message($message, $is_error = false) {
        $url = $this->get_admin_page_url();
        $url = add_query_arg([
            'message' => rawurlencode((string) $message),
            'type' => $is_error ? 'error' : 'success',
        ], $url);

        wp_safe_redirect($url);
        exit;
    }

    private function get_admin_page_url() {
        if (is_multisite()) {
            return network_admin_url('settings.php?page=webo-hmac-connect-trolywp');
        }

        return admin_url('options-general.php?page=webo-hmac-connect-trolywp');
    }

    private function get_portal_state() {
        $key = 'webo_hmac_trolywp_state';
        $value = is_multisite() ? get_site_option($key, []) : get_option($key, []);

        return is_array($value) ? $value : [];
    }

    private function save_portal_state($data) {
        $key = 'webo_hmac_trolywp_state';
        $state = $this->get_portal_state();

        foreach ($data as $k => $v) {
            $state[$k] = $v;
        }

        if (is_multisite()) {
            update_site_option($key, $state);
            return;
        }

        update_option($key, $state, false);
    }

    private function get_webo_mcp_version() {
        $plugin_file = WP_PLUGIN_DIR . '/webo-mcp/webo-mcp.php';
        if (!is_file($plugin_file)) {
            return '';
        }

        $headers = get_file_data($plugin_file, ['Version' => 'Version']);
        return isset($headers['Version']) ? sanitize_text_field((string) $headers['Version']) : '';
    }
}
