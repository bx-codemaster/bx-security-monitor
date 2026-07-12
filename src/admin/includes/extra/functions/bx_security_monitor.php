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

function msec_check_patch_status(string $target, string $backup): string {
  $meta_file = $backup . '.meta';

  // Kein Backup -> Patch wurde nie installiert (oder sauber zurückgesetzt)
  if (!file_exists($backup)) {
    return 'not_installed';
  }

  if (!file_exists($meta_file)) {
    // Backup existiert, aber Meta fehlt -> unklarer Zustand, sollte eigentlich nie passieren
    return 'meta_missing';
  }

  $meta = json_decode(file_get_contents($meta_file), true);
  if (!is_array($meta) || empty($meta['patched_hash'])) {
    return 'meta_invalid';
  }

  if (!file_exists($target)) {
    // Zieldatei fehlt komplett - kritisch!
    return 'target_missing';
  }

  $current_hash = hash_file('sha256', $target);

  if ($current_hash === $meta['patched_hash']) {
    return 'ok';
  }

  return 'mismatch'; // Core-Update oder Fremdänderung hat den Patch überschrieben
}

/**
 * Gibt den Patch-Status in der Admin-Oberfläche aus.
 * @param string $status
 * @param array $messages
 */
function msec_render_patch_status(string $status, array $messages): void {
    $style_map = [
        'ok'            => ['class' => 'success_message', 'icon' => '✅'],
        'not_installed' => ['class' => 'warning_message', 'icon' => 'ℹ️'],
        'mismatch'      => ['class' => 'warning_message', 'icon' => '⚠️'],
        'target_missing'=> ['class' => 'warning_message', 'icon' => '⚠️'],
        'meta_invalid'  => ['class' => 'warning_message', 'icon' => '⚠️'],
        'meta_missing'  => ['class' => 'error_message',   'icon' => '❌'],
        'unknown'       => ['class' => 'error_message',   'icon' => '❌'],
    ];

    $style = $style_map[$status] ?? ['class' => 'warning_message', 'icon' => '⚠️'];
    $text  = $messages[$status]  ?? $messages['unknown'] ?? 'Unbekannter Status';

    echo '<div class="'.$style['class'].'" style="padding: 5px;">'.$style['icon'].' '.$text.'</div>';
}

/**
 * Spiegelt die msec_whitelist-Tabelle als reine Textdatei, damit
 * xss_secure.php (läuft VOR der DB-Verbindung in application_top.php)
 * die Whitelist ohne DB-Zugriff auswerten kann.
 */
function bx_sync_whitelist_file(): bool {
    global $messageStack;

    $file = DIR_FS_CATALOG . 'log/msec_whitelist_mirror.log';
    $tmp  = $file . '.tmp';

    $rows = xtc_db_query("SELECT ip_address FROM msec_whitelist");
    if (!$rows) {
        $messageStack->add_session('Whitelist-Spiegeldatei konnte nicht aktualisiert werden (DB-Fehler).', 'error');
        return false;
    }

    $ips = array();
    while ($row = xtc_db_fetch_array($rows)) {
        $ip = trim((string)$row['ip_address']);
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            $ips[] = $ip;
        }
    }

    $written = @file_put_contents($tmp, implode("\n", $ips));
    if ($written === false) {
        $messageStack->add_session('Whitelist-Spiegeldatei konnte nicht geschrieben werden. Prüfe Schreibrechte auf ' . dirname($file), 'error');
        @unlink($tmp);
        return false;
    }

    if (!@rename($tmp, $file)) {
        $messageStack->add_session('Whitelist-Spiegeldatei konnte nicht aktiviert werden.', 'error');
        @unlink($tmp);
        return false;
    }

    return true;
}
