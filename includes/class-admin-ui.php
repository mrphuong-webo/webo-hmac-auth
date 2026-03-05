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
     * Register network admin hooks only.
     */
    public function register() {
        if (!is_multisite()) {
            return;
        }

        add_action('network_admin_menu', [$this, 'register_menu']);
        add_action('admin_menu', [$this, 'register_user_menu']);
        add_action('network_admin_edit_webo_hmac_create_key', [$this, 'handle_create_key']);
        add_action('network_admin_edit_webo_hmac_revoke_key', [$this, 'handle_revoke_key']);
        add_action('network_admin_edit_webo_hmac_rotate_key', [$this, 'handle_rotate_key']);
        add_action('admin_post_webo_hmac_rotate_own_key', [$this, 'handle_rotate_own_key']);
        add_action('edit_user_profile', [$this, 'render_network_user_edit_section']);
    }

    /**
     * Add network admin page.
     */
    public function register_menu() {
        add_users_page(
            'WEBO API Keys',
            'WEBO API Keys',
            'manage_network_options',
            'webo-hmac-auth',
            [$this, 'render_page']
        );
    }

    /**
     * Add users.php page for regular users to rotate their own keys.
     */
    public function register_user_menu() {
        if (is_network_admin()) {
            return;
        }

        add_users_page(
            'WEBO API Keys',
            'WEBO API Keys',
            'read',
            'webo-hmac-auth',
            [$this, 'render_page']
        );
    }

    /**
     * Render key list + create form.
     */
    public function render_page() {
        $is_network_manager = current_user_can('manage_network_options');
        if (!$is_network_manager && !current_user_can('read')) {
            wp_die(esc_html__('You do not have permission to access this page.', 'webo-hmac-auth'));
        }

        $current_user_id = get_current_user_id();
        $clients = $is_network_manager
            ? $this->key_manager->list_clients()
            : $this->key_manager->list_clients_by_user($current_user_id);

        $users = [];
        $user_sites_map = [];
        $scope_suggestions = $this->get_scope_suggestions();
        if ($is_network_manager) {
            $users = get_users([
                'fields' => ['ID', 'user_login'],
                'number' => 500,
                'orderby' => 'user_login',
                'order' => 'ASC',
            ]);

            foreach ($users as $user) {
                $blogs = get_blogs_of_user((int) $user->ID, true);
                $sites = [];

                if (is_array($blogs)) {
                    foreach ($blogs as $blog_id => $blog) {
                        $site_id = isset($blog->userblog_id) ? (int) $blog->userblog_id : (int) $blog_id;
                        $site_name = isset($blog->blogname) && '' !== (string) $blog->blogname ? (string) $blog->blogname : 'Site #' . $site_id;
                        $site_url = isset($blog->siteurl) ? (string) $blog->siteurl : '';

                        $sites[] = [
                            'id' => $site_id,
                            'name' => $site_name,
                            'url' => $site_url,
                        ];
                    }
                }

                $user_sites_map[(string) $user->ID] = $sites;
            }
        }

        $secret_notice = get_site_transient($this->get_secret_notice_key());
        if ($secret_notice) {
            delete_site_transient($this->get_secret_notice_key());
        }

        $status_message = isset($_GET['message']) ? sanitize_text_field(wp_unslash($_GET['message'])) : '';
        $status_type = isset($_GET['type']) ? sanitize_key(wp_unslash($_GET['type'])) : 'success';

        ?>
        <div class="wrap">
            <h1><?php echo esc_html__('WEBO API Keys (HMAC)', 'webo-hmac-auth'); ?></h1>
            <p><?php echo esc_html__('Use these keys for WEBO MCP and WP Abilities endpoints with HMAC signatures.', 'webo-hmac-auth'); ?></p>

            <?php if ('' !== $status_message) : ?>
                <div class="notice <?php echo ('error' === $status_type) ? 'notice-error' : 'notice-success'; ?> is-dismissible">
                    <p><?php echo esc_html(rawurldecode($status_message)); ?></p>
                </div>
            <?php endif; ?>

            <?php if (!empty($secret_notice) && is_array($secret_notice)) : ?>
                <div class="notice notice-success is-dismissible">
                    <p><strong><?php echo esc_html__('Secret (shown once):', 'webo-hmac-auth'); ?></strong></p>
                    <p><?php echo esc_html($secret_notice['key_id']); ?> : <code><?php echo esc_html($secret_notice['secret']); ?></code></p>
                    <p><?php echo esc_html__('Copy now. Secret cannot be retrieved later.', 'webo-hmac-auth'); ?></p>
                </div>
            <?php endif; ?>

            <?php if ($is_network_manager) : ?>
                <h2><?php echo esc_html__('Create Key', 'webo-hmac-auth'); ?></h2>
                <form method="post" action="<?php echo esc_url(network_admin_url('edit.php?action=webo_hmac_create_key')); ?>">
                    <?php wp_nonce_field('webo_hmac_create_key'); ?>
                    <table class="form-table" role="presentation">
                        <tr>
                            <th scope="row"><label for="wp_user_id"><?php echo esc_html__('Mapped WP User', 'webo-hmac-auth'); ?></label></th>
                            <td>
                                <select id="wp_user_id" name="wp_user_id" required>
                                    <option value=""><?php echo esc_html__('Select user', 'webo-hmac-auth'); ?></option>
                                    <?php foreach ($users as $user) : ?>
                                        <option value="<?php echo esc_attr($user->ID); ?>"><?php echo esc_html($user->user_login . ' (#' . $user->ID . ')'); ?></option>
                                    <?php endforeach; ?>
                                </select>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><label for="allowed_sites"><?php echo esc_html__('Allowed Sites', 'webo-hmac-auth'); ?></label></th>
                            <td>
                                <select id="allowed_sites_picker" multiple size="6" style="min-width:420px;"></select>
                                <input id="allowed_sites" name="allowed_sites" type="text" class="regular-text" readonly />
                                <p class="description"><?php echo esc_html__('Select sites that mapped user can access. Empty means all sites.', 'webo-hmac-auth'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><label for="allowlist"><?php echo esc_html__('Allowlist (JSON array)', 'webo-hmac-auth'); ?></label></th>
                            <td>
                                <select id="allowlist_picker" multiple size="8" style="min-width:420px;">
                                    <?php foreach ($scope_suggestions as $scope_item) : ?>
                                        <option value="<?php echo esc_attr($scope_item); ?>"><?php echo esc_html($scope_item); ?></option>
                                    <?php endforeach; ?>
                                </select>
                                <textarea id="allowlist" name="allowlist" rows="4" cols="60" placeholder='["webo/list-posts","webo-list-plugins"]'></textarea>
                                <p class="description"><?php echo esc_html__('Pick from list to auto-generate JSON. If set, only listed tools/abilities are allowed.', 'webo-hmac-auth'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><label for="denylist"><?php echo esc_html__('Denylist (JSON array)', 'webo-hmac-auth'); ?></label></th>
                            <td>
                                <select id="denylist_picker" multiple size="8" style="min-width:420px;">
                                    <?php foreach ($scope_suggestions as $scope_item) : ?>
                                        <option value="<?php echo esc_attr($scope_item); ?>"><?php echo esc_html($scope_item); ?></option>
                                    <?php endforeach; ?>
                                </select>
                                <textarea id="denylist" name="denylist" rows="4" cols="60" placeholder='["webo/delete-post"]'></textarea>
                                <p class="description"><?php echo esc_html__('Pick from list to auto-generate JSON. Denied items always win over allowlist.', 'webo-hmac-auth'); ?></p>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><label for="rate_limit"><?php echo esc_html__('Rate limit / minute', 'webo-hmac-auth'); ?></label></th>
                            <td>
                                <input id="rate_limit" name="rate_limit" type="number" min="1" step="1" value="60" />
                            </td>
                        </tr>
                    </table>
                    <?php submit_button(__('Create Key', 'webo-hmac-auth')); ?>
                </form>

                <script>
                (function () {
                    const userSitesMap = <?php echo wp_json_encode($user_sites_map); ?>;
                    const userSelect = document.getElementById('wp_user_id');
                    const sitePicker = document.getElementById('allowed_sites_picker');
                    const siteInput = document.getElementById('allowed_sites');
                    const allowPicker = document.getElementById('allowlist_picker');
                    const allowInput = document.getElementById('allowlist');
                    const denyPicker = document.getElementById('denylist_picker');
                    const denyInput = document.getElementById('denylist');

                    function selectedValues(selectEl) {
                        return Array.from(selectEl.selectedOptions).map(function (opt) { return opt.value; });
                    }

                    function syncSitesInput() {
                        siteInput.value = selectedValues(sitePicker).join(',');
                    }

                    function syncJsonInput(selectEl, textareaEl) {
                        const values = selectedValues(selectEl);
                        textareaEl.value = values.length ? JSON.stringify(values) : '';
                    }

                    function renderSites(userId) {
                        const sites = userSitesMap[userId] || [];
                        sitePicker.innerHTML = '';

                        sites.forEach(function (site) {
                            const option = document.createElement('option');
                            option.value = String(site.id);
                            option.textContent = site.name + ' (#' + site.id + ')' + (site.url ? ' - ' + site.url : '');
                            sitePicker.appendChild(option);
                        });

                        syncSitesInput();
                    }

                    if (userSelect && sitePicker && siteInput) {
                        userSelect.addEventListener('change', function () {
                            renderSites(userSelect.value || '');
                        });
                        sitePicker.addEventListener('change', syncSitesInput);
                        renderSites(userSelect.value || '');
                    }

                    if (allowPicker && allowInput) {
                        allowPicker.addEventListener('change', function () {
                            syncJsonInput(allowPicker, allowInput);
                        });
                    }

                    if (denyPicker && denyInput) {
                        denyPicker.addEventListener('change', function () {
                            syncJsonInput(denyPicker, denyInput);
                        });
                    }
                })();
                </script>

                <hr />
            <?php endif; ?>

            <h2><?php echo esc_html__('Key List', 'webo-hmac-auth'); ?></h2>
            <table class="widefat striped">
                <thead>
                    <tr>
                        <th><?php echo esc_html__('ID', 'webo-hmac-auth'); ?></th>
                        <th><?php echo esc_html__('Key ID', 'webo-hmac-auth'); ?></th>
                        <?php if ($is_network_manager) : ?>
                            <th><?php echo esc_html__('WP User', 'webo-hmac-auth'); ?></th>
                        <?php endif; ?>
                        <th><?php echo esc_html__('Rate Limit', 'webo-hmac-auth'); ?></th>
                        <th><?php echo esc_html__('Status', 'webo-hmac-auth'); ?></th>
                        <th><?php echo esc_html__('Last Used', 'webo-hmac-auth'); ?></th>
                        <th><?php echo esc_html__('Created', 'webo-hmac-auth'); ?></th>
                        <th><?php echo esc_html__('Actions', 'webo-hmac-auth'); ?></th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($clients)) : ?>
                        <tr>
                            <td colspan="<?php echo $is_network_manager ? '8' : '7'; ?>"><?php echo esc_html__('No API keys found.', 'webo-hmac-auth'); ?></td>
                        </tr>
                    <?php else : ?>
                        <?php foreach ($clients as $client) : ?>
                            <tr>
                                <td><?php echo esc_html((string) $client['id']); ?></td>
                                <td><code><?php echo esc_html($client['key_id']); ?></code></td>
                                <?php if ($is_network_manager) : ?>
                                    <td><?php echo esc_html(($client['user_login'] ?: 'unknown') . ' (#' . (int) $client['wp_user_id'] . ')'); ?></td>
                                <?php endif; ?>
                                <td><?php echo esc_html((string) $client['rate_limit']); ?></td>
                                <td><?php echo esc_html((string) $client['status']); ?></td>
                                <td><?php echo esc_html((string) ($client['last_used_at'] ?: '-')); ?></td>
                                <td><?php echo esc_html((string) $client['created_at']); ?></td>
                                <td>
                                    <?php if ('active' === $client['status']) : ?>
                                        <?php if ($is_network_manager) : ?>
                                            <form method="post" action="<?php echo esc_url(network_admin_url('edit.php?action=webo_hmac_rotate_key')); ?>" style="display:inline-block;margin-right:6px;">
                                                <?php wp_nonce_field('webo_hmac_rotate_key_' . (int) $client['id']); ?>
                                                <input type="hidden" name="id" value="<?php echo esc_attr((string) $client['id']); ?>" />
                                                <button type="submit" class="button button-secondary"><?php echo esc_html__('Rotate', 'webo-hmac-auth'); ?></button>
                                            </form>
                                            <form method="post" action="<?php echo esc_url(network_admin_url('edit.php?action=webo_hmac_revoke_key')); ?>" style="display:inline-block;">
                                                <?php wp_nonce_field('webo_hmac_revoke_key_' . (int) $client['id']); ?>
                                                <input type="hidden" name="id" value="<?php echo esc_attr((string) $client['id']); ?>" />
                                                <button type="submit" class="button button-link-delete" onclick="return confirm('<?php echo esc_js(__('Revoke this key?', 'webo-hmac-auth')); ?>');"><?php echo esc_html__('Revoke', 'webo-hmac-auth'); ?></button>
                                            </form>
                                        <?php else : ?>
                                            <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" style="display:inline-block;margin-right:6px;">
                                                <input type="hidden" name="action" value="webo_hmac_rotate_own_key" />
                                                <?php wp_nonce_field('webo_hmac_rotate_own_key_' . (int) $client['id']); ?>
                                                <input type="hidden" name="id" value="<?php echo esc_attr((string) $client['id']); ?>" />
                                                <button type="submit" class="button button-secondary"><?php echo esc_html__('Rotate', 'webo-hmac-auth'); ?></button>
                                            </form>
                                        <?php endif; ?>
                                    <?php else : ?>
                                        <em><?php echo esc_html__('Revoked', 'webo-hmac-auth'); ?></em>
                                    <?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
        <?php
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
     * Handle user self-rotation submission from users.php.
     */
    public function handle_rotate_own_key() {
        if (!current_user_can('read')) {
            wp_die(esc_html__('You are not allowed to do this.', 'webo-hmac-auth'));
        }

        $id = isset($_POST['id']) ? (int) wp_unslash($_POST['id']) : 0;
        check_admin_referer('webo_hmac_rotate_own_key_' . $id);

        $result = $this->key_manager->rotate_secret_for_user($id, get_current_user_id());
        if (is_wp_error($result)) {
            $this->redirect_with_message($result->get_error_message(), true, false);
        }

        set_site_transient($this->get_secret_notice_key(), [
            'key_id' => $result['key_id'],
            'secret' => $result['secret'],
        ], 300);

        $this->redirect_with_message('Secret rotated. New secret is shown once.', false, false);
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
                    <form method="post" action="<?php echo esc_url(network_admin_url('edit.php?action=webo_hmac_create_key')); ?>">
                        <?php wp_nonce_field('webo_hmac_create_key'); ?>
                        <input type="hidden" name="wp_user_id" value="<?php echo esc_attr((string) $user->ID); ?>" />
                        <input type="hidden" name="redirect_to" value="<?php echo esc_attr($redirect_to); ?>" />
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
                            <button type="submit" class="button button-primary"><?php echo esc_html__('Create Key', 'webo-hmac-auth'); ?></button>
                        </p>
                    </form>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php echo esc_html__('Existing keys', 'webo-hmac-auth'); ?></th>
                <td>
                    <?php if (empty($clients)) : ?>
                        <p><?php echo esc_html__('No keys for this user.', 'webo-hmac-auth'); ?></p>
                    <?php else : ?>
                        <table class="widefat striped">
                            <thead>
                                <tr>
                                    <th><?php echo esc_html__('Key ID', 'webo-hmac-auth'); ?></th>
                                    <th><?php echo esc_html__('Rate', 'webo-hmac-auth'); ?></th>
                                    <th><?php echo esc_html__('Status', 'webo-hmac-auth'); ?></th>
                                    <th><?php echo esc_html__('Last Used', 'webo-hmac-auth'); ?></th>
                                    <th><?php echo esc_html__('Actions', 'webo-hmac-auth'); ?></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($clients as $client) : ?>
                                    <tr>
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

                    <script>
                    (function () {
                        const uid = '<?php echo esc_js((string) $user->ID); ?>';
                        const sitePicker = document.getElementById('webo_allowed_sites_picker_' + uid);
                        const siteInput = document.getElementById('webo_allowed_sites_' + uid);
                        const allowPicker = document.getElementById('webo_allowlist_picker_' + uid);
                        const allowInput = document.getElementById('webo_allowlist_' + uid);
                        const denyPicker = document.getElementById('webo_denylist_picker_' + uid);
                        const denyInput = document.getElementById('webo_denylist_' + uid);

                        function selectedValues(selectEl) {
                            return Array.from(selectEl.selectedOptions).map(function (opt) { return opt.value; });
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
