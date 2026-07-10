<?php
/**
 * Copy to `config.php` (not versioned) and fill in.
 */

return [
    // PageSpeed Insights API key — free.
    // https://console.cloud.google.com/apis/credentials → enable "PageSpeed Insights API".
    // Without a key the API still works, but the shared quota runs out very fast.
    'pagespeed_key' => '',

    // Notification on each completed test. Leave empty to disable.
    'notify_to'   => 'you@example.com',
    'notify_from' => 'noreply@example.com',
];
