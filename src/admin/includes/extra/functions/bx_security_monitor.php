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

function msec_core_patch_registry(): array {
  return array(
    'login_admin' => array(
      'modified-3.3.0' => array(
        'original' => 'login_admin.original.php',
        'patched' => 'login_admin.patched.php',
      ),
    ),
    'xss_secure' => array(
      'modified-3.3.0-security-update' => array(
        'original' => 'xss_secure.original.php',
        'patched' => 'xss_secure.patched.php',
      ),'modified-3.3.0-beforesecurity-update' => array(
        'original' => 'xss_before_secure.original.php',
        'patched' => 'xss_before_secure.patched.php',
      ),
    ),
  );
}

function msec_core_patch_pairs(string $type): array {
  return msec_validate_core_patch_pairs($type, msec_core_patch_registry());
}

function msec_updated_patch_pair(array $pairs, string $backup_hash, string $old_patch_hash, string $target_hash): ?array {
  if (!isset($pairs[$backup_hash]) || $pairs[$backup_hash]['patched_hash'] !== $old_patch_hash) {
    return null;
  }
  $match = null;
  foreach ($pairs as $original_hash => $pair) {
    if ($pair['patched_hash'] === $target_hash && $original_hash !== $backup_hash) {
      if ($match !== null) {
        throw new RuntimeException('Ambiguous updated core patch');
      }
      $pair['original_hash'] = $original_hash;
      $match = $pair;
    }
  }
  return $match;
}

function msec_validate_core_patch_pairs(string $type, array $versions): array {
  $directory = DIR_FS_CATALOG . 'includes/data/';
  if (!is_array($versions) || empty($versions[$type]) || !is_array($versions[$type])) {
    throw new RuntimeException('Core patch versions are missing for ' . $type);
  }

  $pairs = array();
  foreach ($versions[$type] as $version => $pair) {
    if (!is_string($version) || $version === '' || !is_array($pair)
        || !isset($pair['original'], $pair['patched'])
        || !is_string($pair['original']) || !is_string($pair['patched'])
        || strpbrk($pair['original'], '/\\') !== false || strpbrk($pair['patched'], '/\\') !== false
        || !is_file($directory . $pair['original']) || !is_file($directory . $pair['patched'])) {
      throw new RuntimeException('Invalid core patch pair for ' . $type . ': ' . $version);
    }
    $original = $directory . $pair['original'];
    $patched = $directory . $pair['patched'];
    $original_hash = hash_file('sha256', $original);
    $patched_hash = hash_file('sha256', $patched);
    if ($original_hash === false || $patched_hash === false || isset($pairs[$original_hash])) {
      throw new RuntimeException('Unreadable or ambiguous core patch pair for ' . $type . ': ' . $version);
    }
    $pairs[$original_hash] = array(
      'version' => $version,
      'original' => $original,
      'patched' => $patched,
      'patched_hash' => $patched_hash,
    );
  }
  return $pairs;
}

function msec_check_patch_status(string $target, string $backup, ?string $patch_type = null): string {
  $meta_file = $backup . '.meta';

  // Kein Backup -> Patch wurde nie installiert (oder sauber zurückgesetzt)
  if (!file_exists($backup)) {
    return file_exists($meta_file) ? 'meta_invalid' : 'not_installed';
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

  if ($current_hash === $meta['patched_hash'] && $patch_type !== null) {
    try {
      $pairs = msec_core_patch_pairs($patch_type);
    } catch (RuntimeException $e) {
      error_log('Core patch status: ' . $e->getMessage());
      return 'unknown';
    }
    $backup_hash = hash_file('sha256', $backup);
    if ($backup_hash === false || empty($meta['original_hash'])
        || $backup_hash !== $meta['original_hash']
        || !isset($pairs[$backup_hash])
        || $current_hash !== $pairs[$backup_hash]['patched_hash']) {
      return 'mismatch';
    }
  }
  if ($current_hash !== false && $current_hash === $meta['patched_hash']) {
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
