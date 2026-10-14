<?php
/* ==================================================
   MVNBC settings store
   Reads/writes config/settings.json (alert + notification config).
   Shared by the Alerts page, the notifier, and the backup runner.
================================================== */

if (!function_exists('mvnbc_settings_path')) {

    function mvnbc_settings_path() {
        $base = realpath(__DIR__ . "/../../..");
        return $base . "/config/settings.json";
    }

    function mvnbc_default_settings() {
        return [
            'alerts' => [
                'notify_on'      => 'failure',   // 'failure' | 'always' | 'never'
            ],
            'email' => [
                'enabled'    => false,
                'smtp_host'  => '',
                'smtp_port'  => 587,
                'smtp_secure'=> 'tls',           // 'tls' | 'ssl' | 'none'
                'username'   => '',
                'password'   => '',
                'from'       => '',
                'to'         => '',              // comma separated
            ],
            'telegram' => [
                'enabled'   => false,
                'bot_token' => '',
                'chat_id'   => '',
            ],
        ];
    }

    function mvnbc_load_settings() {
        $path = mvnbc_settings_path();
        $defaults = mvnbc_default_settings();
        if (!is_file($path)) return $defaults;
        $raw = @file_get_contents($path);
        if ($raw === false || trim($raw) === '') return $defaults;
        $data = json_decode($raw, true);
        if (!is_array($data)) return $defaults;
        // deep-merge so missing keys fall back to defaults
        foreach ($defaults as $section => $vals) {
            if (!isset($data[$section]) || !is_array($data[$section])) {
                $data[$section] = $vals;
            } else {
                $data[$section] = array_merge($vals, $data[$section]);
            }
        }
        return $data;
    }

    function mvnbc_save_settings($data) {
        $path = mvnbc_settings_path();
        $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        $res  = @file_put_contents($path, $json, LOCK_EX);
        if ($res !== false) { @chmod($path, 0600); }
        return $res !== false;
    }
}
