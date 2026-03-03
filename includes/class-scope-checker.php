<?php

namespace WeboHmacAuth;

use WP_Error;

if (!defined('ABSPATH')) {
    exit;
}

class ScopeChecker {
    /**
     * Check if route should be protected by HMAC auth.
     *
     * @param string $path Request path.
     *
     * @return bool
     */
    public function is_protected_route($path) {
        $path = (string) $path;

        return false !== strpos($path, '/wp-json/mcp/')
            || false !== strpos($path, '/wp-json/wp-abilities/');
    }

    /**
     * Enforce site and tool/ability scopes.
     *
     * @param array  $client   Client row.
     * @param string $path     Request path.
     * @param string $raw_body Raw request body.
     *
     * @return true|WP_Error
     */
    public function enforce($client, $path, $raw_body) {
        $allowed_sites = $this->decode_json_array(isset($client['allowed_sites']) ? $client['allowed_sites'] : null);
        if (!empty($allowed_sites)) {
            $current_blog_id = (int) get_current_blog_id();
            if (!in_array($current_blog_id, $allowed_sites, true)) {
                return new WP_Error(
                    'webo_scope_site_denied',
                    'This API key is not allowed for current site.',
                    ['status' => 403]
                );
            }
        }

        $target_name = $this->extract_target_name($path, $raw_body);
        if ('' === $target_name) {
            // For MCP methods like initialize/tools/list there is no scope target.
            return true;
        }

        $denylist = $this->decode_json_array(isset($client['denylist']) ? $client['denylist'] : null);
        if (!empty($denylist) && in_array($target_name, $denylist, true)) {
            return new WP_Error(
                'webo_scope_denylist',
                'Requested tool/ability is denied for this key.',
                ['status' => 403]
            );
        }

        $allowlist = $this->decode_json_array(isset($client['allowlist']) ? $client['allowlist'] : null);
        if (!empty($allowlist) && !in_array($target_name, $allowlist, true)) {
            return new WP_Error(
                'webo_scope_allowlist',
                'Requested tool/ability is not in allowlist for this key.',
                ['status' => 403]
            );
        }

        return true;
    }

    /**
     * Extract target tool/ability name for scope checks.
     *
     * @param string $path     Request path.
     * @param string $raw_body Raw request body.
     *
     * @return string
     */
    private function extract_target_name($path, $raw_body) {
        $path = (string) $path;

        // MCP: only enforce per-tool scope on tools/call.
        if (false !== strpos($path, '/wp-json/mcp/')) {
            $payload = json_decode((string) $raw_body, true);
            if (!is_array($payload)) {
                return '';
            }

            if (($payload['method'] ?? '') !== 'tools/call') {
                return '';
            }

            $tool_name = isset($payload['params']['name']) ? sanitize_text_field((string) $payload['params']['name']) : '';
            return $tool_name;
        }

        // Abilities run route: /wp-json/wp-abilities/v1/abilities/{ability}/run
        if (preg_match('#/wp-json/wp-abilities/v\d+/abilities/(.+?)/run/?$#', $path, $matches)) {
            return sanitize_text_field(rawurldecode($matches[1]));
        }

        return '';
    }

    /**
     * Decode list-like JSON stored in DB.
     *
     * @param string|null $json Raw DB JSON.
     *
     * @return array
     */
    private function decode_json_array($json) {
        if (empty($json)) {
            return [];
        }

        $decoded = json_decode((string) $json, true);
        if (!is_array($decoded)) {
            return [];
        }

        $normalized = [];
        foreach ($decoded as $item) {
            if (is_scalar($item)) {
                $value = sanitize_text_field((string) $item);
                if ('' !== $value) {
                    $normalized[] = $value;
                }
            }
        }

        return array_values(array_unique($normalized));
    }
}
