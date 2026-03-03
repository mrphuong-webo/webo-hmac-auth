<?php

namespace WeboHmacAuth;

use WP_Error;

if (!defined('ABSPATH')) {
    exit;
}

class RateLimiter {
    /**
     * Apply per-key per-minute rate limiting using network transients.
     *
     * @param string $key_id API key id.
     * @param int    $limit  Allowed requests per minute.
     *
     * @return true|WP_Error
     */
    public function check_and_increment($key_id, $limit) {
        $limit = max(1, (int) $limit);
        $bucket = (int) floor(time() / 60);
        $transient_key = 'webo_rl_' . sanitize_key($key_id) . '_' . $bucket;

        $count = (int) get_site_transient($transient_key);
        $count++;

        // Expire shortly after the minute window rolls over.
        set_site_transient($transient_key, $count, 70);

        if ($count > $limit) {
            return new WP_Error(
                'webo_rate_limited',
                'Too many requests',
                ['status' => 429]
            );
        }

        return true;
    }
}
