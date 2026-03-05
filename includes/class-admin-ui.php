<?php

namespace WeboHmacAuth;

if (!defined('ABSPATH')) {
    exit;
}

class AdminUi {
    /** @var KeyManager */
    private $key_manager;

    /**
     * @param KeyManager $key_manager Key manager service.
     */
    public function __construct(KeyManager $key_manager) {
        $this->key_manager = $key_manager;
    }

    /**
     * Register hooks for network user-edit key management.
     */
    public function register() {
        if (!is_multisite()) {
            return;
        }

        add_action('network_admin_edit_webo_hmac_create_key', [$this, 'handle_create_key']);
        add_action('network_admin_edit_webo_hmac_revoke_key', [$this, 'handle_revoke_key']);
        add_action('network_admin_edit_webo_hmac_rotate_key', [$this, 'handle_rotate_key']);
        add_action('wp_ajax_webo_hmac_create_key_ajax', [$this, 'handle_create_key_ajax']);
        add_action('edit_user_profile', [$this, 'render_network_user_edit_section']);
    }

    /**
     * Handle create key submission.
     */
    public function handle_create_key() {
        if (!current_user_can('manage_network_options')) {
            wp_die(esc_html__('You are not allowed to do this.', 'webo-hmac-auth'));
        }

        check_admin_referer('webo_hmac_create_key');

        $payload = [
            'wp_user_id'    => isset($_POST['wp_user_id']) ? wp_unslash($_POST['wp_user_id']) : '',
            'key_name'      => isset($_POST['key_name']) ? wp_unslash($_POST['key_name']) : '',
            'allowed_sites' => isset($_POST['allowed_sites']) ? wp_unslash($_POST['allowed_sites']) : '',
            'allowlist'     => isset($_POST['allowlist']) ? wp_unslash($_POST['allowlist']) : '',
            'denylist'      => isset($_POST['denylist']) ? wp_unslash($_POST['denylist']) : '',
            'rate_limit'    => isset($_POST['rate_limit']) ? wp_unslash($_POST['rate_limit']) : '60',
        ];

        $result = $this->key_manager->create_client($payload);

        if (is_wp_error($result)) {
            $this->redirect_with_message($result->get_error_message(), true);
        }

        set_site_transient($this->get_secret_notice_key(), [
            'key_id' => $result['key_id'],
            'secret' => $result['secret'],
        ], 300);

        $redirect_to = isset($_POST['redirect_to']) ? wp_unslash($_POST['redirect_to']) : '';
        $this->redirect_with_message('API key created. Secret is shown once.', false, true, $redirect_to);
    }

    /**
     * Handle create key submission via AJAX for user-edit screen.
     */
    public function handle_create_key_ajax() {
        if (!current_user_can('manage_network_options')) {
            wp_send_json_error([
                'message' => __('You are not allowed to do this.', 'webo-hmac-auth'),
            ], 403);
        }

        check_ajax_referer('webo_hmac_create_key');

        $payload = [
            'wp_user_id'    => isset($_POST['wp_user_id']) ? wp_unslash($_POST['wp_user_id']) : '',
            'key_name'      => isset($_POST['key_name']) ? wp_unslash($_POST['key_name']) : '',
            'allowed_sites' => isset($_POST['allowed_sites']) ? wp_unslash($_POST['allowed_sites']) : '',
            'allowlist'     => isset($_POST['allowlist']) ? wp_unslash($_POST['allowlist']) : '',
            'denylist'      => isset($_POST['denylist']) ? wp_unslash($_POST['denylist']) : '',
            'rate_limit'    => isset($_POST['rate_limit']) ? wp_unslash($_POST['rate_limit']) : '60',
        ];

        $result = $this->key_manager->create_client($payload);
        if (is_wp_error($result)) {
            wp_send_json_error([
                'message' => $result->get_error_message(),
            ], 400);
        }

        wp_send_json_success([
            'message' => __('API key created. Secret is shown once.', 'webo-hmac-auth'),
            'key_id'  => $result['key_id'],
            'secret'  => $result['secret'],
            'key_name' => isset($result['key_name']) ? (string) $result['key_name'] : '',
            'rate_limit' => isset($result['rate_limit']) ? (int) $result['rate_limit'] : (int) $payload['rate_limit'],
            'status' => isset($result['status']) ? (string) $result['status'] : 'active',
            'last_used_at' => isset($result['last_used_at']) && '' !== (string) $result['last_used_at'] ? (string) $result['last_used_at'] : '-',
        ]);
    }

    /**
     * Handle revoke key submission.
     */
    public function handle_revoke_key() {
        if (!current_user_can('manage_network_options')) {
            wp_die(esc_html__('You are not allowed to do this.', 'webo-hmac-auth'));
        }

        $id = isset($_POST['id']) ? (int) wp_unslash($_POST['id']) : 0;
        check_admin_referer('webo_hmac_revoke_key_' . $id);

        if ($id <= 0 || !$this->key_manager->revoke_client($id)) {
            $redirect_to = isset($_POST['redirect_to']) ? wp_unslash($_POST['redirect_to']) : '';
            $this->redirect_with_message('Failed to revoke key.', true, true, $redirect_to);
        }

        $redirect_to = isset($_POST['redirect_to']) ? wp_unslash($_POST['redirect_to']) : '';
        $this->redirect_with_message('API key revoked.', false, true, $redirect_to);
    }

    /**
     * Handle rotate secret submission.
     */
    public function handle_rotate_key() {
        if (!current_user_can('manage_network_options')) {
            wp_die(esc_html__('You are not allowed to do this.', 'webo-hmac-auth'));
        }

        $id = isset($_POST['id']) ? (int) wp_unslash($_POST['id']) : 0;
        check_admin_referer('webo_hmac_rotate_key_' . $id);

        $result = $this->key_manager->rotate_secret($id);
        if (is_wp_error($result)) {
            $redirect_to = isset($_POST['redirect_to']) ? wp_unslash($_POST['redirect_to']) : '';
            $this->redirect_with_message($result->get_error_message(), true, true, $redirect_to);
        }

        set_site_transient($this->get_secret_notice_key(), [
            'key_id' => $result['key_id'],
            'secret' => $result['secret'],
        ], 300);

        $redirect_to = isset($_POST['redirect_to']) ? wp_unslash($_POST['redirect_to']) : '';
        $this->redirect_with_message('Secret rotated. New secret is shown once.', false, true, $redirect_to);
    }

    /**
     * Render key settings section directly in Network Admin user edit screen.
     *
     * @param \WP_User $user Edited user object.
     */
    public function render_network_user_edit_section($user) {
        if (!is_network_admin() || !current_user_can('manage_network_options')) {
            return;
        }

        if (!($user instanceof \WP_User) || empty($user->ID)) {
            return;
        }

        $clients = $this->key_manager->list_clients_by_user((int) $user->ID);
        $user_blogs = get_blogs_of_user((int) $user->ID, true);
        $scope_suggestions = $this->get_scope_suggestions();
        $status_message = isset($_GET['message']) ? sanitize_text_field(wp_unslash($_GET['message'])) : '';
        $status_type = isset($_GET['type']) ? sanitize_key(wp_unslash($_GET['type'])) : 'success';
        $redirect_to = network_admin_url('user-edit.php?user_id=' . (int) $user->ID);

        ?>
        <h2><?php echo esc_html__('WEBO API Keys (HMAC)', 'webo-hmac-auth'); ?></h2>

        <?php if ('' !== $status_message) : ?>
            <div class="notice <?php echo ('error' === $status_type) ? 'notice-error' : 'notice-success'; ?> inline">
                <p><?php echo esc_html(rawurldecode($status_message)); ?></p>
            </div>
        <?php endif; ?>

        <table class="form-table" role="presentation">
            <tr>
                <th scope="row"><?php echo esc_html__('Create new key for this user', 'webo-hmac-auth'); ?></th>
                <td>
                    <div id="webo_create_key_form_<?php echo esc_attr((string) $user->ID); ?>">
                        <input type="hidden" name="wp_user_id" value="<?php echo esc_attr((string) $user->ID); ?>" />
                        <input type="hidden" name="redirect_to" value="<?php echo esc_attr($redirect_to); ?>" />
                        <p>
                            <label for="webo_key_name_<?php echo esc_attr((string) $user->ID); ?>"><?php echo esc_html__('Key Name', 'webo-hmac-auth'); ?></label><br />
                            <input id="webo_key_name_<?php echo esc_attr((string) $user->ID); ?>" name="key_name" type="text" class="regular-text" maxlength="191" placeholder="example: n8n-prod, mobile-app, agent-01" />
                        </p>
                        <p>
                            <label for="webo_allowed_sites_<?php echo esc_attr((string) $user->ID); ?>"><?php echo esc_html__('Allowed Sites', 'webo-hmac-auth'); ?></label><br />
                            <select id="webo_allowed_sites_picker_<?php echo esc_attr((string) $user->ID); ?>" multiple size="6" style="min-width:420px;">
                                <?php if (is_array($user_blogs)) : ?>
                                    <?php foreach ($user_blogs as $blog_id => $blog) : ?>
                                        <?php
                                        $site_id = isset($blog->userblog_id) ? (int) $blog->userblog_id : (int) $blog_id;
                                        $site_name = isset($blog->blogname) && '' !== (string) $blog->blogname ? (string) $blog->blogname : 'Site #' . $site_id;
                                        $site_url = isset($blog->siteurl) ? (string) $blog->siteurl : '';
                                        ?>
                                        <option value="<?php echo esc_attr((string) $site_id); ?>"><?php echo esc_html($site_name . ' (#' . $site_id . ')' . ($site_url ? ' - ' . $site_url : '')); ?></option>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                            </select>
                            <input id="webo_allowed_sites_<?php echo esc_attr((string) $user->ID); ?>" name="allowed_sites" type="text" class="regular-text" readonly />
                        </p>
                        <p>
                            <label for="webo_allowlist_<?php echo esc_attr((string) $user->ID); ?>"><?php echo esc_html__('Allowlist (JSON array)', 'webo-hmac-auth'); ?></label><br />
                            <select id="webo_allowlist_picker_<?php echo esc_attr((string) $user->ID); ?>" multiple size="8" style="min-width:420px;">
                                <?php foreach ($scope_suggestions as $scope_item) : ?>
                                    <option value="<?php echo esc_attr($scope_item); ?>"><?php echo esc_html($scope_item); ?></option>
                                <?php endforeach; ?>
                            </select>
                            <textarea id="webo_allowlist_<?php echo esc_attr((string) $user->ID); ?>" name="allowlist" rows="3" cols="60" placeholder='["webo/list-posts"]'></textarea>
                        </p>
                        <p>
                            <label for="webo_denylist_<?php echo esc_attr((string) $user->ID); ?>"><?php echo esc_html__('Denylist (JSON array)', 'webo-hmac-auth'); ?></label><br />
                            <select id="webo_denylist_picker_<?php echo esc_attr((string) $user->ID); ?>" multiple size="8" style="min-width:420px;">
                                <?php foreach ($scope_suggestions as $scope_item) : ?>
                                    <option value="<?php echo esc_attr($scope_item); ?>"><?php echo esc_html($scope_item); ?></option>
                                <?php endforeach; ?>
                            </select>
                            <textarea id="webo_denylist_<?php echo esc_attr((string) $user->ID); ?>" name="denylist" rows="3" cols="60" placeholder='["webo/delete-post"]'></textarea>
                        </p>
                        <p>
                            <label for="webo_rate_limit_<?php echo esc_attr((string) $user->ID); ?>"><?php echo esc_html__('Rate limit / minute', 'webo-hmac-auth'); ?></label><br />
                            <input id="webo_rate_limit_<?php echo esc_attr((string) $user->ID); ?>" name="rate_limit" type="number" min="1" step="1" value="60" />
                        </p>
                        <p>
                            <button id="webo_create_key_button_<?php echo esc_attr((string) $user->ID); ?>" type="button" class="button button-primary"><?php echo esc_html__('Create Key', 'webo-hmac-auth'); ?></button>
                        </p>
                        <div id="webo_create_key_notice_<?php echo esc_attr((string) $user->ID); ?>"></div>
                    </div>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php echo esc_html__('Existing keys', 'webo-hmac-auth'); ?></th>
                <td>
                    <div id="webo_keys_container_<?php echo esc_attr((string) $user->ID); ?>">
                    <?php if (empty($clients)) : ?>
                        <p id="webo_no_keys_<?php echo esc_attr((string) $user->ID); ?>"><?php echo esc_html__('No keys for this user.', 'webo-hmac-auth'); ?></p>
                    <?php else : ?>
                        <table id="webo_keys_table_<?php echo esc_attr((string) $user->ID); ?>" class="widefat striped">
                            <thead>
                                <tr>
                                    <th><?php echo esc_html__('Key Name', 'webo-hmac-auth'); ?></th>
                                    <th><?php echo esc_html__('Key ID', 'webo-hmac-auth'); ?></th>
                                    <th><?php echo esc_html__('Rate', 'webo-hmac-auth'); ?></th>
                                    <th><?php echo esc_html__('Status', 'webo-hmac-auth'); ?></th>
                                    <th><?php echo esc_html__('Last Used', 'webo-hmac-auth'); ?></th>
                                    <th><?php echo esc_html__('Actions', 'webo-hmac-auth'); ?></th>
                                </tr>
                            </thead>
                            <tbody id="webo_keys_tbody_<?php echo esc_attr((string) $user->ID); ?>">
                                <?php foreach ($clients as $client) : ?>
                                    <tr>
                                        <td><?php echo esc_html((string) ($client['key_name'] ?? '-')); ?></td>
                                        <td><code><?php echo esc_html($client['key_id']); ?></code></td>
                                        <td><?php echo esc_html((string) $client['rate_limit']); ?></td>
                                        <td><?php echo esc_html((string) $client['status']); ?></td>
                                        <td><?php echo esc_html((string) ($client['last_used_at'] ?: '-')); ?></td>
                                        <td>
                                            <?php if ('active' === $client['status']) : ?>
                                                <form method="post" action="<?php echo esc_url(network_admin_url('edit.php?action=webo_hmac_rotate_key')); ?>" style="display:inline-block;margin-right:6px;">
                                                    <?php wp_nonce_field('webo_hmac_rotate_key_' . (int) $client['id']); ?>
                                                    <input type="hidden" name="id" value="<?php echo esc_attr((string) $client['id']); ?>" />
                                                    <input type="hidden" name="redirect_to" value="<?php echo esc_attr($redirect_to); ?>" />
                                                    <button type="submit" class="button button-secondary"><?php echo esc_html__('Rotate', 'webo-hmac-auth'); ?></button>
                                                </form>
                                                <form method="post" action="<?php echo esc_url(network_admin_url('edit.php?action=webo_hmac_revoke_key')); ?>" style="display:inline-block;">
                                                    <?php wp_nonce_field('webo_hmac_revoke_key_' . (int) $client['id']); ?>
                                                    <input type="hidden" name="id" value="<?php echo esc_attr((string) $client['id']); ?>" />
                                                    <input type="hidden" name="redirect_to" value="<?php echo esc_attr($redirect_to); ?>" />
                                                    <button type="submit" class="button button-link-delete" onclick="return confirm('<?php echo esc_js(__('Revoke this key?', 'webo-hmac-auth')); ?>');"><?php echo esc_html__('Revoke', 'webo-hmac-auth'); ?></button>
                                                </form>
                                            <?php else : ?>
                                                <em><?php echo esc_html__('Revoked', 'webo-hmac-auth'); ?></em>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php endif; ?>
                    </div>

                    <script>
                    (function () {
                        const uid = '<?php echo esc_js((string) $user->ID); ?>';
                        const sitePicker = document.getElementById('webo_allowed_sites_picker_' + uid);
                        const siteInput = document.getElementById('webo_allowed_sites_' + uid);
                        const allowPicker = document.getElementById('webo_allowlist_picker_' + uid);
                        const allowInput = document.getElementById('webo_allowlist_' + uid);
                        const denyPicker = document.getElementById('webo_denylist_picker_' + uid);
                        const denyInput = document.getElementById('webo_denylist_' + uid);
                        const createForm = document.getElementById('webo_create_key_form_' + uid);
                        const createButton = document.getElementById('webo_create_key_button_' + uid);
                        const createNotice = document.getElementById('webo_create_key_notice_' + uid);
                        const ajaxUrl = '<?php echo esc_js(admin_url('admin-ajax.php')); ?>';
                        const ajaxNonce = '<?php echo esc_js(wp_create_nonce('webo_hmac_create_key')); ?>';
                        const keysContainer = document.getElementById('webo_keys_container_' + uid);
                        const tableId = 'webo_keys_table_' + uid;
                        const tbodyId = 'webo_keys_tbody_' + uid;
                        const noKeysId = 'webo_no_keys_' + uid;

                        function selectedValues(selectEl) {
                            return Array.from(selectEl.selectedOptions).map(function (opt) { return opt.value; });
                        }

                        function escapeHtml(value) {
                            return String(value)
                                .replace(/&/g, '&amp;')
                                .replace(/</g, '&lt;')
                                .replace(/>/g, '&gt;')
                                .replace(/"/g, '&quot;')
                                .replace(/'/g, '&#039;');
                        }

                        function ensureKeysTable() {
                            let table = document.getElementById(tableId);
                            let tbody = document.getElementById(tbodyId);
                            const noKeys = document.getElementById(noKeysId);

                            if (table && tbody) {
                                if (noKeys) {
                                    noKeys.remove();
                                }
                                return tbody;
                            }

                            if (!keysContainer) {
                                return null;
                            }

                            if (noKeys) {
                                noKeys.remove();
                            }

                            table = document.createElement('table');
                            table.id = tableId;
                            table.className = 'widefat striped';
                            table.innerHTML = '<thead><tr>' +
                                '<th><?php echo esc_js(__('Key Name', 'webo-hmac-auth')); ?></th>' +
                                '<th><?php echo esc_js(__('Key ID', 'webo-hmac-auth')); ?></th>' +
                                '<th><?php echo esc_js(__('Rate', 'webo-hmac-auth')); ?></th>' +
                                '<th><?php echo esc_js(__('Status', 'webo-hmac-auth')); ?></th>' +
                                '<th><?php echo esc_js(__('Last Used', 'webo-hmac-auth')); ?></th>' +
                                '<th><?php echo esc_js(__('Actions', 'webo-hmac-auth')); ?></th>' +
                                '</tr></thead>' +
                                '<tbody id="' + tbodyId + '"></tbody>';
                            keysContainer.appendChild(table);
                            return document.getElementById(tbodyId);
                        }

                        function appendCreatedKeyRow(data) {
                            const tbody = ensureKeysTable();
                            if (!tbody) {
                                return;
                            }

                            const keyId = data && data.key_id ? data.key_id : '';
                            const keyName = data && data.key_name ? data.key_name : '-';
                            const rateInput = document.getElementById('webo_rate_limit_' + uid);
                            const rate = data && data.rate_limit ? data.rate_limit : (rateInput ? rateInput.value : '60');
                            const status = data && data.status ? data.status : 'active';
                            const lastUsed = data && data.last_used_at ? data.last_used_at : '-';

                            const row = document.createElement('tr');
                            row.innerHTML = '<td>' + escapeHtml(keyName) + '</td>' +
                                '<td><code>' + escapeHtml(keyId) + '</code></td>' +
                                '<td>' + escapeHtml(rate) + '</td>' +
                                '<td>' + escapeHtml(status) + '</td>' +
                                '<td>' + escapeHtml(lastUsed) + '</td>' +
                                '<td><em><?php echo esc_js(__('Refresh page to manage this key.', 'webo-hmac-auth')); ?></em></td>';

                            if (tbody.firstChild) {
                                tbody.insertBefore(row, tbody.firstChild);
                            } else {
                                tbody.appendChild(row);
                            }
                        }

                        if (sitePicker && siteInput) {
                            sitePicker.addEventListener('change', function () {
                                siteInput.value = selectedValues(sitePicker).join(',');
                            });
                        }

                        if (allowPicker && allowInput) {
                            allowPicker.addEventListener('change', function () {
                                const values = selectedValues(allowPicker);
                                allowInput.value = values.length ? JSON.stringify(values) : '';
                            });
                        }

                        if (denyPicker && denyInput) {
                            denyPicker.addEventListener('change', function () {
                                const values = selectedValues(denyPicker);
                                denyInput.value = values.length ? JSON.stringify(values) : '';
                            });
                        }

                        if (createForm && createButton) {
                            createButton.addEventListener('click', function () {
                                createButton.disabled = true;
                                if (createNotice) {
                                    createNotice.innerHTML = '<div class="notice notice-info inline"><p><?php echo esc_js(__('Creating key...', 'webo-hmac-auth')); ?></p></div>';
                                }

                                const payload = new FormData();
                                payload.append('action', 'webo_hmac_create_key_ajax');
                                payload.append('_ajax_nonce', ajaxNonce);

                                const wpUserInput = createForm.querySelector('input[name="wp_user_id"]');
                                const keyNameInput = createForm.querySelector('input[name="key_name"]');
                                const allowedSitesInput = createForm.querySelector('input[name="allowed_sites"]');
                                const allowlistInput = createForm.querySelector('textarea[name="allowlist"]');
                                const denylistInput = createForm.querySelector('textarea[name="denylist"]');
                                const rateLimitInput = createForm.querySelector('input[name="rate_limit"]');

                                payload.append('wp_user_id', wpUserInput ? wpUserInput.value : uid);
                                payload.append('key_name', keyNameInput ? keyNameInput.value : '');
                                payload.append('allowed_sites', allowedSitesInput ? allowedSitesInput.value : '');
                                payload.append('allowlist', allowlistInput ? allowlistInput.value : '');
                                payload.append('denylist', denylistInput ? denylistInput.value : '');
                                payload.append('rate_limit', rateLimitInput ? rateLimitInput.value : '60');

                                fetch(ajaxUrl, {
                                    method: 'POST',
                                    credentials: 'same-origin',
                                    body: payload
                                })
                                    .then(function (response) {
                                        return response.json();
                                    })
                                    .then(function (payload) {
                                        if (!createNotice) {
                                            return;
                                        }

                                        if (payload && payload.success && payload.data) {
                                            const keyId = payload.data.key_id || '';
                                            const secret = payload.data.secret || '';
                                            const message = payload.data.message || 'API key created.';

                                            createNotice.innerHTML = '<div class="notice notice-success inline"><p><strong>' + message + '</strong><br>' +
                                                'Key ID: <code>' + keyId + '</code><br>' +
                                                'Secret: <code>' + secret + '</code><br>' +
                                                '<?php echo esc_js(__('Copy now. Secret cannot be retrieved later.', 'webo-hmac-auth')); ?></p></div>';

                                            appendCreatedKeyRow(payload.data);
                                        } else {
                                            const errMsg = payload && payload.data && payload.data.message ? payload.data.message : '<?php echo esc_js(__('Failed to create key.', 'webo-hmac-auth')); ?>';
                                            createNotice.innerHTML = '<div class="notice notice-error inline"><p>' + errMsg + '</p></div>';
                                        }
                                    })
                                    .catch(function () {
                                        if (createNotice) {
                                            createNotice.innerHTML = '<div class="notice notice-error inline"><p><?php echo esc_js(__('Request failed. Please try again.', 'webo-hmac-auth')); ?></p></div>';
                                        }
                                    })
                                    .finally(function () {
                                        createButton.disabled = false;
                                    });
                            });
                        }
                    })();
                    </script>
                </td>
            </tr>
        </table>
        <?php
    }

    /**
     * Returns predefined scope suggestions for allowlist/denylist pickers.
     *
     * @return array<int, string>
     */
    private function get_scope_suggestions() {
        $suggestions = [
            'webo/get-site-info',
            'webo/list-posts',
            'webo/get-post',
            'webo/create-post',
            'webo/update-post',
            'webo/delete-post',
            'webo/list-users',
            'webo/list-media',
            'webo/list-comments',
            'webo/list-terms',
            'webo/list-active-plugins',
            'webo/get-options',
            'webo/update-options',
            'webo-featured/create-featured',
            'webo-featured/get-featured',
            'webo-featured/update-featured',
            'webo-featured/delete-featured',
            'webo-featured/list-featured',
            'post-order/get-list',
            'post-order/set-order',
            'post-order/get-tax-order',
            'post-order/set-tax-order',
            'post-order/update-item',
            'post-order/reset',
            'post-order/set-top-items',
            'core/get-site-info',
            'core/get-user-info',
            'core/get-environment-info',
        ];

        return array_values(array_unique(array_filter(array_map('strval', $suggestions))));
    }

    /**
     * Redirect back to plugin page with status message.
     *
     * @param string $message Message text.
     * @param bool   $error   Error status.
     */
    private function redirect_with_message($message, $error = false, $network_context = true, $redirect_to = '') {
        $base_url = $network_context ? network_admin_url('admin.php') : admin_url('users.php');

        if (!empty($redirect_to)) {
            $validated = wp_validate_redirect((string) $redirect_to, '');
            if (!empty($validated)) {
                $base_url = $validated;
            }
        }

        $url = add_query_arg(
            [
                'message' => rawurlencode((string) $message),
                'type'    => $error ? 'error' : 'success',
            ],
            $base_url
        );

        wp_safe_redirect($url);
        exit;
    }

    /**
     * Build secret notice transient key per admin user.
     *
     * @return string
     */
    private function get_secret_notice_key() {
        return 'webo_hmac_secret_notice_' . get_current_user_id();
    }
}
