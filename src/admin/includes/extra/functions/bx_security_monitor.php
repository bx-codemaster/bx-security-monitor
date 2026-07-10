<?php
/**
 * Konfigurationseingabefeld für die Modulversion (read-only)
 */
if (!function_exists('bx_configuration_field_version')) {
  function bx_configuration_field_version(string $value, string $constant): string {
    return xtc_draw_input_field( 'configuration['.$constant.']', $value, 'readonly="true" style="opacity: 0.4;"');
  }
}

function msec_admin_h(string $value): string {
    return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

function msec_admin_short(string $value, int $length = 100): string {
    if (function_exists('mb_strlen') && mb_strlen($value, 'UTF-8') > $length) {
        return mb_substr($value, 0, $length - 3, 'UTF-8') . '...';
    }
    return strlen($value) > $length ? substr($value, 0, $length - 3) . '...' : $value;
}

function msec_admin_table_exists(string $table): bool|int {
    $query = xtc_db_query("SHOW TABLES LIKE '" . xtc_db_input($table) . "'");
    return xtc_db_num_rows($query) > 0;
}

function msec_admin_column_exists(string $table, string $column): bool|int {
    $query = xtc_db_query("SHOW COLUMNS FROM " . $table . " LIKE '" . xtc_db_input($column) . "'");
    return xtc_db_num_rows($query) > 0;
}

function msec_admin_redirect(): void {
    xtc_redirect(xtc_href_link('msec_security.php'));
}

function msec_admin_config_upsert(string $key, string $value, string $title, string $description, int $sort_order): void {
    $table  = defined('TABLE_CONFIGURATION') ? TABLE_CONFIGURATION : 'configuration';
    $exists = xtc_db_query("SELECT configuration_id FROM " . $table . " WHERE configuration_key = '" . xtc_db_input($key) . "' LIMIT 1");

    if (xtc_db_num_rows($exists) > 0) {
        xtc_db_query("UPDATE " . $table . " SET configuration_value = '" . xtc_db_input($value) . "', last_modified = NOW() WHERE configuration_key = '" . xtc_db_input($key) . "'");
        return;
    }

    $data = array(
        'configuration_title' => $title,
        'configuration_key' => $key,
        'configuration_value' => $value,
        'configuration_description' => $description,
        'configuration_group_id' => 6,
        'sort_order' => (int)$sort_order,
        'date_added' => 'now()',
        'use_function' => '',
        'set_function' => ''
    );
    xtc_db_perform($table, $data);
}

function msec_admin_rebuild_rule_cache() {
    if (!msec_admin_table_exists('msec_manual_rules')) {
        return;
    }

    $rules = array();
    $query = xtc_db_query("SELECT pattern, 
                                         match_type, 
                                         score 
                                   FROM msec_manual_rules 
                                  WHERE is_enabled = 1 ORDER BY rule_id ASC");
    while ($row = xtc_db_fetch_array($query)) {
        $rules[] = array(
            'pattern'    => $row['pattern'],
            'match_type' => $row['match_type'],
            'score'      => (int)$row['score']
        );
    }

    $cache = base64_encode(json_encode($rules, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));
    xtc_db_query("UPDATE " . TABLE_CONFIGURATION . " SET configuration_value = '" . xtc_db_prepare_input($cache) . "', last_modified = NOW() WHERE configuration_key = 'MODULE_BX_SECURITY_MANUAL_RULES_CACHE'");
}
