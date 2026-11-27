<?php
/* ---------------------------------------------------------
   $Id: bx_security_monitor.php 00000 2026-07-10 00:00:00Z benax $

   modified eCommerce Shopsoftware
   http://www.modified-shop.org

   Copyright (c) 2009 - 2013 [www.modified-shop.org]
   ---------------------------------------------------------

   Released under the GNU General Public License 
   -------------------------------------------------------*/

  class bx_security_monitor {
    public string $code;
    public string $title;
    public string $description;
    public int    $sort_order;
    public bool   $enabled;
    private bool  $_check;
	  public string $development_status; // 'p' = production ready, 'd' = in development, '' = Idee/Konzept
    public string $version;

    public function __construct() {
      $this->code        = 'bx_security_monitor';
      $this->title       = MODULE_BX_SECURITY_MONITOR_STATUS_TITLE;
      $this->description = MODULE_BX_SECURITY_MONITOR_STATUS_DESC;
      $this->sort_order  = defined('MODULE_BX_SECURITY_MONITOR_SORT_ORDER') ? (int)MODULE_BX_SECURITY_MONITOR_SORT_ORDER : 0;
      $this->enabled     = ((defined('MODULE_BX_SECURITY_MONITOR_STATUS') && MODULE_BX_SECURITY_MONITOR_STATUS == 'True') ? true : false);
      $this->development_status = 'p';
      $this->version     = '1.5.2';
    }

    public function process($file): void {
    }

    public function display(): array {
      return array('text' => '<div style="text-align: center;">'.xtc_button(BUTTON_SAVE).xtc_button_link(BUTTON_CANCEL, xtc_href_link(FILENAME_MODULE_EXPORT, 'set='.$_GET['set'].'&module='.$this->code))."</div>");
    }

    public function check(): mixed {
      if (!isset($this->_check)) {
        $check_query = xtc_db_query("SELECT configuration_value 
                                      FROM ".TABLE_CONFIGURATION."
                                      WHERE configuration_key = 'MODULE_BX_SECURITY_MONITOR_STATUS'");
        $this->_check = xtc_db_num_rows($check_query);
      }
      return $this->_check;
    }

    public function install(): void {      
      xtc_db_query("ALTER TABLE " . TABLE_ADMIN_ACCESS . " ADD bx_security_monitor INTEGER(1)");
      xtc_db_query("UPDATE ".TABLE_ADMIN_ACCESS." SET bx_security_monitor = 1");

      $freeId_query = xtc_db_query("SELECT MIN(configuration_group_id+1) AS id 
                                            FROM ".TABLE_CONFIGURATION_GROUP." 
                                          WHERE (configuration_group_id+1) NOT IN 
                                            (SELECT configuration_group_id FROM ".TABLE_CONFIGURATION_GROUP." WHERE configuration_group_id IS NOT NULL);");
      $freeId = xtc_db_fetch_array($freeId_query);

      $freeSort_query = xtc_db_query("SELECT MIN(sort_order+1) AS sort_order 
                                              FROM ".TABLE_CONFIGURATION_GROUP." 
                                            WHERE (sort_order+1) NOT IN (SELECT sort_order FROM ".TABLE_CONFIGURATION_GROUP." WHERE sort_order IS NOT NULL)");
      $freeSort = xtc_db_fetch_array($freeSort_query);

      xtc_db_query("INSERT INTO ".TABLE_CONFIGURATION_GROUP." ( configuration_group_id, 
                                                                configuration_group_title, 
                                                                configuration_group_description, 
                                                                sort_order, 
                                                                visible ) 
                                                      VALUES ( '" . (int)$freeId['id'] . "', 
                                                                '" . xtc_db_input('BX Security Monitor') . "', 
                                                                '" . xtc_db_input('Settings for the BX Security Monitor module') . "', 
                                                                '" . (int)$freeSort['sort_order'] . "',
                                                                1 );");

      xtc_db_query("INSERT INTO ".TABLE_CONFIGURATION." ( configuration_id, 
                                                          configuration_key, 
                                                          configuration_value, 
                                                          configuration_group_id, 
                                                          sort_order, 
                                                          set_function, 
                                                          date_added ) 
                                                VALUES ( '', 
                                                          'MODULE_BX_SECURITY_MONITOR_STATUS', 
                                                          'True',  
                                                          '6', 
                                                          '1', 
                                                          'xtc_cfg_select_option(array(\'True\', \'False\'), ',
                                                          now() );");

      xtc_db_query("INSERT INTO " . TABLE_CONFIGURATION . " ( configuration_key,
                                                              configuration_value,
                                                              configuration_group_id,
                                                              sort_order,
                                                              use_function,
                                                              set_function,
                                                              date_added)
                                                            VALUES ('MODULE_BX_SECURITY_MONITOR_CONFIG_GROUP_ID',
                                                              '".(int)$freeId['id']."',
                                                              '6', 
                                                              '2',
                                                              NULL,
                                                              'bx_configuration_field_version(',
                                                              now())");

      xtc_db_query("INSERT INTO " . TABLE_CONFIGURATION . " ( configuration_key,
                                                              configuration_value,
                                                              configuration_group_id,
                                                              sort_order,
                                                              use_function,
                                                              set_function,
                                                              date_added)
                                                            VALUES ('MODULE_BX_SECURITY_SCANNER_STATUS',
                                                              'True', 
                                                              '".(int)$freeId['id']."',
                                                              '1',
                                                              NULL,
                                                              'xtc_cfg_select_option(array(\'True\', \'False\'), ', 
                                                              now())");

      xtc_db_query("INSERT INTO " . TABLE_CONFIGURATION . " ( configuration_key,
                                                              configuration_value,
                                                              configuration_group_id,
                                                              sort_order,
                                                              use_function,
                                                              set_function,
                                                              date_added)
                                                            VALUES ('MODULE_BX_SECURITY_BLOCK_THRESHOLD',
                                                              '25', 
                                                              '".(int)$freeId['id']."',
                                                              '2',
                                                              NULL,
                                                              '',
                                                              now())");

      xtc_db_query("INSERT INTO " . TABLE_CONFIGURATION . " ( configuration_key,
                                                              configuration_value,
                                                              configuration_group_id,
                                                              sort_order,
                                                              use_function,
                                                              set_function,
                                                              date_added)
                                                            VALUES ('MODULE_BX_SECURITY_SCORE_WINDOW_MINUTES',
                                                              '10', 
                                                              '".(int)$freeId['id']."',
                                                              '3',
                                                              NULL,
                                                              '',
                                                              now())");

      xtc_db_query("INSERT INTO " . TABLE_CONFIGURATION . " ( configuration_key,
                                                              configuration_value,
                                                              configuration_group_id,
                                                              sort_order,
                                                              use_function,
                                                              set_function,
                                                              date_added)
                                                            VALUES ('MODULE_BX_SECURITY_BLOCK_HOURS',
                                                              '24', 
                                                              '".(int)$freeId['id']."',
                                                              '4',
                                                              NULL,
                                                              '',
                                                              now())");

      xtc_db_query("INSERT INTO " . TABLE_CONFIGURATION . " ( configuration_key,
                                                              configuration_value,
                                                              configuration_group_id,
                                                              sort_order,
                                                              use_function,
                                                              set_function,
                                                              date_added)
                                                            VALUES ('MODULE_BX_SECURITY_EVENT_RETENTION_DAYS',
                                                              '14', 
                                                              '".(int)$freeId['id']."',
                                                              '5',
                                                              NULL,
                                                              '',
                                                              now())");

      xtc_db_query("INSERT INTO " . TABLE_CONFIGURATION . " ( configuration_key,
                                                              configuration_value,
                                                              configuration_group_id,
                                                              sort_order,
                                                              use_function,
                                                              set_function,
                                                              date_added)
                                                            VALUES ('MODULE_BX_SECURITY_ADMIN_LOGIN_STATUS',
                                                              'True', 
                                                              '".(int)$freeId['id']."',
                                                              '6',
                                                              NULL,
                                                              'xtc_cfg_select_option(array(\'True\', \'False\'), ', 
                                                              now())");

      xtc_db_query("INSERT INTO " . TABLE_CONFIGURATION . " ( configuration_key,
                                                              configuration_value,
                                                              configuration_group_id,
                                                              sort_order,
                                                              use_function,
                                                              set_function,
                                                              date_added)
                                                            VALUES ('MODULE_BX_SECURITY_ADMIN_LOGIN_MAX_ATTEMPTS',
                                                              '10', 
                                                              '".(int)$freeId['id']."',
                                                              '7',
                                                              NULL,
                                                              '', 
                                                              now())");

      xtc_db_query("INSERT INTO " . TABLE_CONFIGURATION . " ( configuration_key,
                                                              configuration_value,
                                                              configuration_group_id,
                                                              sort_order,
                                                              use_function,
                                                              set_function,
                                                              date_added)
                                                            VALUES ('MODULE_BX_SECURITY_ADMIN_LOGIN_WINDOW_MINUTES',
                                                              '15', 
                                                              '".(int)$freeId['id']."',
                                                              '8',
                                                              NULL,
                                                              '', 
                                                              now())");

      xtc_db_query("INSERT INTO " . TABLE_CONFIGURATION . " ( configuration_key,
                                                              configuration_value,
                                                              configuration_group_id,
                                                              sort_order,
                                                              use_function,
                                                              set_function,
                                                              date_added)
                                                            VALUES ('MODULE_BX_SECURITY_ADMIN_LOGIN_BLOCK_MINUTES',
                                                              '60', 
                                                              '".(int)$freeId['id']."',
                                                              '9',
                                                              NULL,
                                                              '', 
                                                              now())");

      xtc_db_query("INSERT INTO " . TABLE_CONFIGURATION . " ( configuration_key,
                                                              configuration_value,
                                                              configuration_group_id,
                                                              sort_order,
                                                              use_function,
                                                              set_function,
                                                              date_added)
                                                            VALUES ('MODULE_BX_SECURITY_MANUAL_RULES_CACHE',
                                                              '', 
                                                              '".(int)$freeId['id']."',
                                                              '10',
                                                              NULL,
                                                              '', 
                                                              now())");

      xtc_db_query("CREATE TABLE IF NOT EXISTS msec_blocks (
          block_id INT(11) NOT NULL AUTO_INCREMENT,
          ip_address VARCHAR(45) NOT NULL,
          reason VARCHAR(255) NOT NULL DEFAULT '',
          score INT(11) NOT NULL DEFAULT 0,
          hits INT(11) NOT NULL DEFAULT 0,
          first_seen DATETIME NOT NULL,
          last_seen DATETIME NOT NULL,
          blocked_until DATETIME DEFAULT NULL,
          is_permanent TINYINT(1) NOT NULL DEFAULT 0,
          user_agent VARCHAR(255) NOT NULL DEFAULT '',
          PRIMARY KEY (block_id),
          UNIQUE KEY ip_address (ip_address),
          KEY blocked_until (blocked_until),
          KEY last_seen (last_seen)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8");

      xtc_db_query("CREATE TABLE IF NOT EXISTS msec_events (
          event_id INT(11) NOT NULL AUTO_INCREMENT,
          ip_address VARCHAR(45) NOT NULL,
          request_uri VARCHAR(600) NOT NULL DEFAULT '',
          request_path VARCHAR(600) NOT NULL DEFAULT '',
          request_method VARCHAR(10) NOT NULL DEFAULT '',
          user_agent VARCHAR(255) NOT NULL DEFAULT '',
          referer VARCHAR(600) NOT NULL DEFAULT '',
          reason VARCHAR(255) NOT NULL DEFAULT '',
          category VARCHAR(120) NOT NULL DEFAULT '',
          score INT(11) NOT NULL DEFAULT 0,
          is_blocked TINYINT(1) NOT NULL DEFAULT 0,
          date_added DATETIME NOT NULL,
          PRIMARY KEY (event_id),
          KEY ip_address (ip_address),
          KEY date_added (date_added),
          KEY category (category),
          KEY score (score)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8");

      xtc_db_query("CREATE TABLE IF NOT EXISTS msec_whitelist (
          whitelist_id INT(11) NOT NULL AUTO_INCREMENT,
          ip_address VARCHAR(45) NOT NULL,
          note VARCHAR(255) NOT NULL DEFAULT '',
          date_added DATETIME NOT NULL,
          PRIMARY KEY (whitelist_id),
          UNIQUE KEY ip_address (ip_address)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8");

      xtc_db_query("CREATE TABLE IF NOT EXISTS msec_admin_sessions (
          temp_id INT(11) NOT NULL AUTO_INCREMENT,
          ip_address VARCHAR(45) NOT NULL,
          admin_customers_id INT(11) NOT NULL DEFAULT 0,
          admin_session_id VARCHAR(128) NOT NULL DEFAULT '',
          date_added DATETIME NOT NULL,
          last_seen DATETIME NOT NULL,
          expires_at DATETIME NOT NULL,
          PRIMARY KEY (temp_id),
          UNIQUE KEY ip_session (ip_address, admin_session_id),
          KEY ip_address (ip_address),
          KEY expires_at (expires_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8");

      xtc_db_query("CREATE TABLE IF NOT EXISTS msec_manual_rules (
          rule_id INT(11) NOT NULL AUTO_INCREMENT,
          pattern VARCHAR(255) NOT NULL,
          match_type VARCHAR(20) NOT NULL DEFAULT 'contains',
          score INT(11) NOT NULL DEFAULT 25,
          is_enabled TINYINT(1) NOT NULL DEFAULT 1,
          hit_count INT(11) NOT NULL DEFAULT 0,
          date_added DATETIME NOT NULL,
          last_hit DATETIME DEFAULT NULL,
          PRIMARY KEY (rule_id),
          KEY is_enabled (is_enabled)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8");

      $admin_patch_ok = $this->bx_patch_login_admin();
      $xss_patch_ok   = $this->bx_patch_xss_secure();
    }

    public function remove(): void {
      global $messageStack;
      if (!$this->bx_can_unpatch_core('xss_secure') || !$this->bx_can_unpatch_core('login_admin')) {
        return;
      }
      if (!$this->bx_unpatch_xss_secure()) {
        return;
      }
      if (!$this->bx_unpatch_login_admin()) {
        return;
      }
      xtc_db_query("DELETE FROM " . TABLE_CONFIGURATION . " WHERE configuration_key IN ('" . implode("', '", $this->keys()) . "')");
      xtc_db_query("DELETE FROM " . TABLE_CONFIGURATION . " WHERE configuration_key IN ('" . implode("', '", $this->keys2()) . "')");
      xtc_db_query("DELETE FROM " . TABLE_CONFIGURATION_GROUP . " WHERE configuration_group_title = 'BX Security Monitor'");

      xtc_db_query("DROP TABLE IF EXISTS `msec_blocks`");
      xtc_db_query("DROP TABLE IF EXISTS `msec_events`");
      xtc_db_query("DROP TABLE IF EXISTS `msec_whitelist`");
      xtc_db_query("DROP TABLE IF EXISTS `msec_admin_sessions`");
      xtc_db_query("DROP TABLE IF EXISTS `msec_manual_rules`");

      xtc_db_query("ALTER TABLE " . TABLE_ADMIN_ACCESS . " DROP COLUMN bx_security_monitor");

      if(file_exists(DIR_FS_CATALOG . 'log/msec_whitelist_mirror.log')) {
        unlink(DIR_FS_CATALOG . 'log/msec_whitelist_mirror.log');
      }
    }

    public function keys(): array {
      return array(
        'MODULE_BX_SECURITY_MONITOR_STATUS',
        'MODULE_BX_SECURITY_MONITOR_CONFIG_GROUP_ID',
      );
    }

    public function keys2(): array {
      return array(
        'MODULE_BX_SECURITY_SCANNER_STATUS',
        'MODULE_BX_SECURITY_BLOCK_THRESHOLD',
        'MODULE_BX_SECURITY_SCORE_WINDOW_MINUTES',
        'MODULE_BX_SECURITY_BLOCK_HOURS',
        'MODULE_BX_SECURITY_EVENT_RETENTION_DAYS',
        'MODULE_BX_SECURITY_ADMIN_LOGIN_STATUS',
        'MODULE_BX_SECURITY_ADMIN_LOGIN_MAX_ATTEMPTS',
        'MODULE_BX_SECURITY_ADMIN_LOGIN_WINDOW_MINUTES',
        'MODULE_BX_SECURITY_ADMIN_LOGIN_BLOCK_MINUTES',
        'MODULE_BX_SECURITY_MANUAL_RULES_CACHE',
      );
    }

    public function custom(): never {
      global $messageStack;
      $result = true;

      if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        $messageStack->add_session(MODULE_BX_SECURITY_MONITOR_TEXT_INVALID_REMOVAL_REQUEST, 'error');
        xtc_redirect(xtc_href_link(FILENAME_MODULE_EXPORT, 'set=system'));
      }
      if ($this->check()) {
        $messageStack->add_session(MODULE_BX_SECURITY_MONITOR_TEXT_UNINSTALL_FIRST, 'error');
        xtc_redirect(xtc_href_link(FILENAME_MODULE_EXPORT, 'set=system'));
      }
      foreach (array('login_admin.php', 'includes/xss_secure.php') as $core_file) {
        $backup = DIR_FS_CATALOG . $core_file . '.bx-backup';
        if (file_exists($backup) || is_link($backup) || file_exists($backup . '.meta') || is_link($backup . '.meta')) {
          $messageStack->add_session(MODULE_BX_SECURITY_MONITOR_TEXT_BACKUP_REMAINS, 'error');
          xtc_redirect(xtc_href_link(FILENAME_MODULE_EXPORT, 'set=system'));
        }
      }

      // Dateien definieren
      $dirs_and_files   = array();
      
      $dirs_and_files[] = DIR_FS_ADMIN . 'bx_security_monitor.php';
      $dirs_and_files[] = DIR_FS_ADMIN . 'images/icons/heading/bx-security-monitor.png';
      $dirs_and_files[] = DIR_FS_ADMIN . 'includes/extra/css/bx_security_monitor.php';
      $dirs_and_files[] = DIR_FS_ADMIN . 'includes/extra/filenames/bx_security_monitor.php';
      $dirs_and_files[] = DIR_FS_ADMIN . 'includes/extra/javascript/bx_security_monitor.php';
      $dirs_and_files[] = DIR_FS_ADMIN . 'includes/extra/menu/bx_security_monitor.php';
      $registry = msec_core_patch_registry();
      foreach (array('login_admin', 'xss_secure') as $type) {
        if (empty($registry[$type]) || !is_array($registry[$type])) {
          error_log('Core patch cleanup: missing registry for ' . $type);
          $messageStack->add_session(sprintf(BX_SECURITY_MONITOR_CORE_PATCH_REGISTRY_ERROR, 'Core-Patches'), 'error');
          xtc_redirect(xtc_href_link(FILENAME_MODULE_EXPORT, 'set=system'));
        }
        foreach ($registry[$type] as $pair) {
          foreach (array('original', 'patched') as $key) {
            if (!is_array($pair) || !isset($pair[$key]) || !is_string($pair[$key])
                || !preg_match('/\A[a-zA-Z0-9_-][a-zA-Z0-9_.-]*\z/', $pair[$key])) {
              error_log('Core patch cleanup: invalid reference filename for ' . $type);
              $messageStack->add_session(sprintf(BX_SECURITY_MONITOR_CORE_PATCH_REGISTRY_ERROR, 'Core-Patches'), 'error');
              xtc_redirect(xtc_href_link(FILENAME_MODULE_EXPORT, 'set=system'));
            }
            $dirs_and_files[] = DIR_FS_CATALOG . 'includes/data/' . $pair[$key];
          }
        }
      }
      $dirs_and_files[] = DIR_FS_CATALOG . 'includes/extra/application_top/application_top_begin/bx_security_bootstrap.php';
      $dirs_and_files[] = DIR_FS_CATALOG . 'includes/extra/application_top/application_top_end/bx_security_session.php';
      $dirs_and_files[] = DIR_FS_CATALOG . 'includes/modules/bx_admin_login_guard.php';
      $dirs_and_files[] = DIR_FS_CATALOG . 'includes/modules/bx_guard.php';
      $dirs_and_files[] = DIR_FS_CATALOG . 'lang/english/extra/admin/bx_security_monitor.php';
      $dirs_and_files[] = DIR_FS_CATALOG . 'lang/german/extra/admin/bx_security_monitor.php';

      // Dateien löschen
      foreach (array_unique($dirs_and_files) as $dir_or_file) {
        if (!$this->secureDelete($dir_or_file)) {
          $messageStack->add_session($dir_or_file.MODULE_BX_SECURITY_MONITOR_TEXT_COULD_NOT_BE_DELETED, 'error');
          $result = false;
        }
      }
      if ($result) {
        foreach (array(
          DIR_FS_ADMIN . 'includes/extra/functions/bx_security_monitor.php',
          DIR_FS_CATALOG . 'lang/english/modules/system/bx_security_monitor.php',
          DIR_FS_CATALOG . 'lang/german/modules/system/bx_security_monitor.php',
        ) as $file) {
          if (!$this->secureDelete($file)) {
            $messageStack->add_session($file.MODULE_BX_SECURITY_MONITOR_TEXT_COULD_NOT_BE_DELETED, 'error');
            $result = false;
            break;
          }
        }
      }

      if ($result && !$this->secureDelete(DIR_FS_ADMIN.'includes/modules/system/bx_security_monitor.php')) {
        $messageStack->add_session(DIR_FS_ADMIN.'includes/modules/system/bx_security_monitor.php'.MODULE_BX_SECURITY_MONITOR_TEXT_COULD_NOT_BE_DELETED, 'error');
        $result = false;
      }
      $messageStack->add_session(
        $result ? MODULE_BX_SECURITY_MONITOR_TEXT_SUCCESSFULLY_REMOVED : MODULE_BX_SECURITY_MONITOR_TEXT_REMOVAL_INCOMPLETE,
        $result ? 'success' : 'error'
      );

      xtc_redirect(xtc_href_link(FILENAME_MODULE_EXPORT, 'set=system'));
    }

    private function secureDelete(string $path): bool {
      if (is_link($path)) {
        return unlink($path);
      }
      if (!file_exists($path)) {
        return true;
      }
      return is_file($path) && unlink($path);
    }

    public function bx_patch_login_admin(): bool {
      return $this->bx_patch_core('login_admin');
    }

    public function bx_patch_xss_secure(): bool {
      return $this->bx_patch_core('xss_secure');
    }

    private function bx_unpatch_login_admin(): bool {
      return $this->bx_unpatch_core('login_admin');
    }

    private function bx_unpatch_xss_secure(): bool {
      return $this->bx_unpatch_core('xss_secure');
    }

    private function bx_patch_core(string $type): bool {
      global $messageStack;

      $file = $type === 'login_admin' ? 'login_admin.php' : 'includes/xss_secure.php';
      $target = DIR_FS_CATALOG . $file;
      $backup = $target . '.bx-backup';
      try {
        $pairs = msec_core_patch_pairs($type);
      } catch (RuntimeException $e) {
        error_log('Core patch: ' . $e->getMessage());
        $messageStack->add_session(sprintf(BX_SECURITY_MONITOR_CORE_PATCH_REGISTRY_ERROR, $file), 'error');
        return false;
      }

      // Rechte prüfen
      if (!is_writable($target) || !is_writable(dirname($target))) {
        $messageStack->add_session('Keine Schreibrechte auf ' . $target, 'error');
        return false;
      }

      $target_hash = hash_file('sha256', $target);
      if ($target_hash === false) {
        $messageStack->add_session(sprintf(BX_SECURITY_MONITOR_CORE_PATCH_HASH_FAILED, $file), 'error');
        return false;
      }

      if (file_exists($backup)) {
        $meta_file = $backup . '.meta';
        $meta = is_file($meta_file) ? json_decode(file_get_contents($meta_file), true) : null;
        $backup_hash = hash_file('sha256', $backup);
        if (!is_array($meta) || empty($meta['original_hash']) || empty($meta['patched_hash'])
            || $backup_hash === false
            || $backup_hash !== $meta['original_hash']) {
          $messageStack->add_session(sprintf(BX_SECURITY_MONITOR_CORE_PATCH_INVALID_BACKUP, $file), 'error');
          return false;
        }

        if ($target_hash === $meta['patched_hash'] && isset($pairs[$backup_hash])
            && $target_hash === $pairs[$backup_hash]['patched_hash']) {
          $messageStack->add_session(sprintf(BX_SECURITY_MONITOR_CORE_PATCH_ALREADY_INSTALLED, $file), 'info');
          return true;
        }

        if ($target_hash === $meta['patched_hash'] && isset($pairs[$backup_hash])) {
          if (!$this->bx_unpatch_core($type)) {
            return false;
          }
          return $this->bx_patch_core($type);
        }

        try {
          $updated_pair = msec_updated_patch_pair($pairs, $backup_hash, $meta['patched_hash'], $target_hash);
        } catch (RuntimeException $e) {
          error_log('Core patch: ' . $e->getMessage());
          $messageStack->add_session(sprintf(BX_SECURITY_MONITOR_CORE_PATCH_REGISTRY_ERROR, $file), 'error');
          return false;
        }
        if ($updated_pair !== null) {
          if (!$this->bx_reconcile_updated_patch($file, $updated_pair, $target_hash, $backup_hash, $meta['patched_hash'])) {
            return false;
          }
          return $this->bx_patch_core($type);
        }

        if (!isset($pairs[$target_hash])) {
          $messageStack->add_session(sprintf(BX_SECURITY_MONITOR_CORE_PATCH_UPDATE_REQUIRED, $file), 'error');
          return false;
        }

        // Preserve the previous core backup before installing over the updated core.
        $previous_backup = $backup . '.previous';
        $previous_meta = $meta_file . '.previous';
        if (file_exists($previous_backup) || file_exists($previous_meta)) {
          $messageStack->add_session(sprintf(BX_SECURITY_MONITOR_CORE_PATCH_ARCHIVE_EXISTS, $file), 'error');
          return false;
        }
        if (!rename($backup, $previous_backup)) {
          $messageStack->add_session(sprintf(BX_SECURITY_MONITOR_CORE_PATCH_ARCHIVE_FAILED, $file), 'error');
          return false;
        }
        if (!rename($meta_file, $previous_meta)) {
          if (!rename($previous_backup, $backup)) {
            $messageStack->add_session(sprintf(BX_SECURITY_MONITOR_CORE_PATCH_ARCHIVE_RESTORE_FAILED, $file), 'error');
          }
          $messageStack->add_session(sprintf(BX_SECURITY_MONITOR_CORE_PATCH_ARCHIVE_FAILED, $file), 'error');
          return false;
        }
        if ($this->bx_patch_core($type)) {
          return true;
        }
        if (file_exists($backup) || file_exists($meta_file)
            || !rename($previous_backup, $backup) || !rename($previous_meta, $meta_file)) {
          $messageStack->add_session(sprintf(BX_SECURITY_MONITOR_CORE_PATCH_ARCHIVE_RESTORE_FAILED, $file), 'error');
        }
        return false;
      }

      if (file_exists($backup . '.meta')) {
        $messageStack->add_session(sprintf(BX_SECURITY_MONITOR_CORE_PATCH_INVALID_BACKUP, $file), 'error');
        return false;
      }

      // Ist die aktuelle Datei noch die erwartete Original-Version?
      // Falls nicht: Core wurde zwischenzeitlich aktualisiert -> abbrechen statt blind patchen.
      if (!isset($pairs[$target_hash])) {
        $messageStack->add_session(sprintf(BX_SECURITY_MONITOR_CORE_PATCH_UPDATE_REQUIRED, $file), 'error');
        return false;
      }
      $pair = $pairs[$target_hash];
      $original_hash = $target_hash;
      $patched_hash = $pair['patched_hash'];
      $patched_src = $pair['patched'];

      // Backup erstellen
      if (!copy($target, $backup)) {
        $messageStack->add_session(sprintf(BX_SECURITY_MONITOR_CORE_PATCH_BACKUP_FAILED, $file), 'error');
        return false;
      }

      // Backup verifizieren
      if (hash_file('sha256', $backup) !== $original_hash) {
        unlink($backup);
        $messageStack->add_session(sprintf(BX_SECURITY_MONITOR_CORE_PATCH_HASH_FAILED, $file), 'error');
        return false;
      }

      // Metadaten sichern (u.a. für spätere Update-Erkennung im Admin-Panel)
      $meta_content = json_encode([
          'original_hash'  => $original_hash,
          'patched_hash'   => $patched_hash,
          'reference_version' => $pair['version'],
          'installed_at'   => date('c'),
          'module_version' => $this->version,
      ], JSON_PRETTY_PRINT);
      $meta_written = file_put_contents($backup . '.meta', $meta_content);

      if ($meta_written !== strlen($meta_content)) {
        // Backup zurückrollen, damit kein halb-installierter Zustand zurückbleibt
        unlink($backup);
        if (file_exists($backup . '.meta')) {
          unlink($backup . '.meta');
        }
        $messageStack->add_session(sprintf(BX_SECURITY_MONITOR_CORE_PATCH_META_WRITE_FAILED, $file), 'error');
        return false;
      }

      // Atomar einspielen: erst als .tmp kopieren, dann umbenennen
      $tmp = $target . '.tmp';

      if (!copy($patched_src, $tmp)) {
        unlink($backup);
        unlink($backup . '.meta');
        $messageStack->add_session('Patched-Datei konnte nicht vorbereitet werden.', 'error');
        return false;
      }

      if (hash_file('sha256', $tmp) !== $patched_hash) {
        unlink($tmp);
        unlink($backup);
        unlink($backup . '.meta');
        $messageStack->add_session(sprintf(BX_SECURITY_MONITOR_CORE_PATCH_HASH_FAILED, $file), 'error');
        return false;
      }

      if (!rename($tmp, $target)) {
        unlink($tmp);
        unlink($backup);
        unlink($backup . '.meta');
        $messageStack->add_session('Patch konnte nicht aktiviert werden.', 'error');
        return false;
      }

      $messageStack->add_session(sprintf(BX_SECURITY_MONITOR_CORE_PATCH_INSTALLED, $file), 'success');
      return true;
    }

    private function bx_reconcile_updated_patch(string $file, array $pair, string $target_hash, string $backup_hash, string $old_patch_hash): bool {
      global $messageStack;

      $target = DIR_FS_CATALOG . $file;
      $backup = $target . '.bx-backup';
      $meta_file = $backup . '.meta';
      $previous_backup = $backup . '.previous';
      $previous_meta = $meta_file . '.previous';
      if (file_exists($previous_backup) || file_exists($previous_meta)) {
        $messageStack->add_session(sprintf(BX_SECURITY_MONITOR_CORE_PATCH_ARCHIVE_EXISTS, $file), 'error');
        return false;
      }
      if (!rename($backup, $previous_backup)) {
        $messageStack->add_session(sprintf(BX_SECURITY_MONITOR_CORE_PATCH_ARCHIVE_FAILED, $file), 'error');
        return false;
      }
      if (!rename($meta_file, $previous_meta)) {
        if (!rename($previous_backup, $backup)) {
          $messageStack->add_session(sprintf(BX_SECURITY_MONITOR_CORE_PATCH_ARCHIVE_RESTORE_FAILED, $file), 'error');
        }
        $messageStack->add_session(sprintf(BX_SECURITY_MONITOR_CORE_PATCH_ARCHIVE_FAILED, $file), 'error');
        return false;
      }

      $meta_content = json_encode([
        'original_hash' => $pair['original_hash'],
        'patched_hash' => $target_hash,
        'reference_version' => $pair['version'],
        'installed_at' => date('c'),
        'module_version' => $this->version,
      ], JSON_PRETTY_PRINT);
      $old_meta = json_decode(file_get_contents($previous_meta), true);
      $ok = hash_file('sha256', $previous_backup) === $backup_hash
          && is_array($old_meta)
          && ($old_meta['original_hash'] ?? null) === $backup_hash
          && ($old_meta['patched_hash'] ?? null) === $old_patch_hash
          && copy($pair['original'], $backup)
          && hash_file('sha256', $backup) === $pair['original_hash']
          && file_put_contents($meta_file, $meta_content) === strlen($meta_content)
          && hash_file('sha256', $target) === $target_hash;
      if ($ok) {
        return true;
      }

      $cleaned = (!file_exists($backup) || unlink($backup));
      $cleaned = (!file_exists($meta_file) || unlink($meta_file)) && $cleaned;
      if (!$cleaned || !rename($previous_backup, $backup) || !rename($previous_meta, $meta_file)) {
        $messageStack->add_session(sprintf(BX_SECURITY_MONITOR_CORE_PATCH_ARCHIVE_RESTORE_FAILED, $file), 'error');
      }
      $messageStack->add_session(sprintf(BX_SECURITY_MONITOR_CORE_PATCH_HASH_FAILED, $file), 'error');
      return false;
    }

    private function bx_can_unpatch_core(string $type): bool {
      global $messageStack;

      $file        = $type === 'login_admin' ? 'login_admin.php' : 'includes/xss_secure.php';
      $target      = DIR_FS_CATALOG . $file;
      $backup      = $target . '.bx-backup';
      $meta_file   = $backup . '.meta';

      if (!file_exists($backup)) {
        if (file_exists($meta_file)) {
          $messageStack->add_session(sprintf(BX_SECURITY_MONITOR_CORE_PATCH_INVALID_BACKUP, $file), 'error');
          return false;
        }
        return true;
      }

      $meta = is_file($meta_file) ? json_decode(file_get_contents($meta_file), true) : null;
      if (!is_array($meta) || empty($meta['original_hash']) || empty($meta['patched_hash'])
          || hash_file('sha256', $backup) !== $meta['original_hash']) {
        $messageStack->add_session(sprintf(BX_SECURITY_MONITOR_CORE_PATCH_INVALID_BACKUP, $file), 'error');
        return false;
      }

      $target_hash = is_file($target) ? hash_file('sha256', $target) : false;
      if ($target_hash !== false && $target_hash !== $meta['patched_hash']) {
        try {
          $updated_pair = msec_updated_patch_pair(msec_core_patch_pairs($type), $meta['original_hash'], $meta['patched_hash'], $target_hash);
        } catch (RuntimeException $e) {
          error_log('Core patch: ' . $e->getMessage());
          $messageStack->add_session(sprintf(BX_SECURITY_MONITOR_CORE_PATCH_REGISTRY_ERROR, $file), 'error');
          return false;
        }
        if ($updated_pair !== null) {
          if (file_exists($backup . '.previous') || file_exists($meta_file . '.previous')) {
            $messageStack->add_session(sprintf(BX_SECURITY_MONITOR_CORE_PATCH_ARCHIVE_EXISTS, $file), 'error');
            return false;
          }
          return true;
        }
      }
      if ($target_hash === false || $target_hash !== $meta['patched_hash']) {
        $messageStack->add_session(
          $file . ' wurde seit der Installation verändert. ' .
          'Automatisches Wiederherstellen wurde abgebrochen, um Datenverlust zu vermeiden. ' .
          'Dein Original-Backup liegt unverändert unter: ' . $backup, 'error'
        );
        return false;
      }
      return true;
    }

    private function bx_unpatch_core(string $type): bool {
      global $messageStack;

      $file = $type === 'login_admin' ? 'login_admin.php' : 'includes/xss_secure.php';
      $target = DIR_FS_CATALOG . $file;
      $backup = $target . '.bx-backup';
      $meta_file = $backup . '.meta';
      if (!$this->bx_can_unpatch_core($type)) {
        return false;
      }
      if (!file_exists($backup)) {
        $messageStack->add_session(sprintf(BX_SECURITY_MONITOR_CORE_PATCH_NOT_INSTALLED, $file), 'info');
        return true;
      }

      $meta = json_decode(file_get_contents($meta_file), true);
      $target_hash = hash_file('sha256', $target);
      if (!is_array($meta) || empty($meta['original_hash']) || empty($meta['patched_hash']) || $target_hash === false) {
        $messageStack->add_session(sprintf(BX_SECURITY_MONITOR_CORE_PATCH_HASH_FAILED, $file), 'error');
        return false;
      }
      if ($target_hash !== $meta['patched_hash']) {
        try {
          $pair = msec_updated_patch_pair(msec_core_patch_pairs($type), $meta['original_hash'], $meta['patched_hash'], $target_hash);
        } catch (RuntimeException $e) {
          error_log('Core patch: ' . $e->getMessage());
          $messageStack->add_session(sprintf(BX_SECURITY_MONITOR_CORE_PATCH_REGISTRY_ERROR, $file), 'error');
          return false;
        }
        if ($pair === null) {
          $messageStack->add_session(sprintf(BX_SECURITY_MONITOR_CORE_PATCH_UPDATE_REQUIRED, $file), 'error');
          return false;
        }
        if (!$this->bx_reconcile_updated_patch($file, $pair, $target_hash, $meta['original_hash'], $meta['patched_hash'])
            || !$this->bx_can_unpatch_core($type)) {
          return false;
        }
      }

      if (!rename($backup, $target)) {
        $messageStack->add_session(sprintf(BX_SECURITY_MONITOR_CORE_PATCH_RESTORE_FAILED, $file), 'error');
        return false;
      }

      if (file_exists($meta_file) && !unlink($meta_file)) {
        $messageStack->add_session(sprintf(BX_SECURITY_MONITOR_CORE_PATCH_META_REMOVE_FAILED, $file), 'error');
        return false;
      }
      $messageStack->add_session(sprintf(BX_SECURITY_MONITOR_CORE_PATCH_RESTORED, $file), 'success');
      return true;
    }
    
  }
