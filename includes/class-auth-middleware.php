<?php

namespace WeboHmacAuth;

use WP_Error;

if (!defined('ABSPATH')) {
    exit;
}

class AuthMiddleware {
    /** @var KeyManager */
    private $key_manager;

    /** @var RateLimiter */
    private $rate_limiter;

    /** @var ScopeChecker */
    private $scope_checker;

    /** @var string|null Cached raw body for current request lifecycle. */
    private static $raw_body_cache = null;

    /**
     * @param KeyManager  $key_manager  Key manager service.
     * @param RateLimiter $rate_limiter Rate limiter service.
     * @param ScopeChecker $scope_checker Scope enforcement service.
     */
    public function __construct(KeyManager $key_manager, RateLimiter $rate_limiter, ScopeChecker $scope_checker) {
        $this->key_manager = $key_manager;
        $this->rate_limiter = $rate_limiter;
        $this->scope_checker = $scope_checker;
    }

    /**
     * Register authentication middleware.
     */
    public function register() {
        add_filter('rest_authentication_errors', [$this, 'authenticate'], 20);
    }

    /**
     * Validate HMAC headers and map API key to WordPress user.
     *
     * @param mixed $result Existing auth result.
     *
     * @return mixed
     */
    public function authenticate($result) {
        // Respect existing auth errors from other auth providers.
        if (is_wp_error($result)) {
            return $result;
        }

        $path = $this->get_request_path();
        if (!$this->scope_checker->is_protected_route($path)) {
            return $result;
        }

        $key_id = $this->get_header('X-WEBO-KEY');
        $timestamp = $this->get_header('X-WEBO-TS');
        $signature = $this->get_header('X-WEBO-SIGN');

        if ('' === $key_id || '' === $timestamp || '' === $signature) {
            return new WP_Error('webo_auth_failed', 'Unauthorized', ['status' => 401]);
        }

        if (!$this->is_timestamp_valid($timestamp)) {
            return new WP_Error('webo_auth_failed', 'Unauthorized', ['status' => 401]);
        }

        $client = $this->key_manager->get_client_by_key_id($key_id);
        if (!$client) {
            return new WP_Error('webo_auth_failed', 'Unauthorized', ['status' => 401]);
        }

        if (($client['status'] ?? '') !== 'active') {
            return new WP_Error('webo_auth_forbidden', 'Forbidden', ['status' => 403]);
        }

        $raw_body = $this->get_raw_body();
        $method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper(sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD']))) : 'GET';

        $valid_signature = $this->key_manager->verify_signature(
            $client,
            $method,
            $path,
            (string) $timestamp,
            $raw_body,
            (string) $signature
        );

        if (!$valid_signature) {
            return new WP_Error('webo_auth_failed', 'Unauthorized', ['status' => 401]);
        }

        $scope_check = $this->scope_checker->enforce($client, $path, $raw_body);
        if (is_wp_error($scope_check)) {
            return $scope_check;
        }

        $rate_check = $this->rate_limiter->check_and_increment($client['key_id'], (int) $client['rate_limit']);
        if (is_wp_error($rate_check)) {
            return $rate_check;
        }

        $wp_user_id = (int) $client['wp_user_id'];
        if ($wp_user_id <= 0 || !get_user_by('id', $wp_user_id)) {
            return new WP_Error('webo_auth_forbidden', 'Forbidden', ['status' => 403]);
        }

        // Map API key identity to WP user so permission_callback remains authoritative.
        wp_set_current_user($wp_user_id);

        // Expose current authenticated client context for same-request integrations
        // (e.g. MCP tool exposure filtering by allowlist/denylist).
        $GLOBALS['webo_hmac_auth_current_client'] = $client;
        do_action('webo_hmac_authenticated_client', $client, $path);

        $this->key_manager->update_last_used($client['key_id']);

        return true;
    }

    /**
     * Resolve request path used for signature base string.
     *
     * @return string
     */
    private function get_request_path() {
        $request_uri = isset($_SERVER['REQUEST_URI']) ? wp_unslash($_SERVER['REQUEST_URI']) : '';
        $path = wp_parse_url($request_uri, PHP_URL_PATH);

        return is_string($path) ? $path : '';
    }

    /**
     * Get request header value in a server-compatible way.
     *
     * @param string $name Header name.
     *
     * @return string
     */
    private function get_header($name) {
        $server_key = 'HTTP_' . strtoupper(str_replace('-', '_', $name));

        if (isset($_SERVER[$server_key])) {
            return sanitize_text_field(wp_unslash($_SERVER[$server_key]));
        }

        if (function_exists('getallheaders')) {
            $headers = getallheaders();
            if (is_array($headers)) {
                foreach ($headers as $header_name => $value) {
                    if (strtolower($header_name) === strtolower($name)) {
                        return sanitize_text_field((string) $value);
                    }
                }
            }
        }

        return '';
    }

    /**
     * Validate timestamp skew <= 120 seconds.
     *
     * @param string $timestamp Header value.
     *
     * @return bool
     */
    private function is_timestamp_valid($timestamp) {
        if (!is_numeric($timestamp)) {
            return false;
        }

        $ts = (int) $timestamp;
        $now = (int) current_time('timestamp');

        return abs($now - $ts) <= 120;
    }

    /**
     * Read and cache raw request body for signature + scope parsing.
     *
     * @return string
     */
    private function get_raw_body() {
        if (null !== self::$raw_body_cache) {
            return self::$raw_body_cache;
        }

        $raw = file_get_contents('php://input');
        self::$raw_body_cache = is_string($raw) ? $raw : '';

        return self::$raw_body_cache;
    }
}
