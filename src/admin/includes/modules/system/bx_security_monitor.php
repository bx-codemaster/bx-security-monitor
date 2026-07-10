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
    public string $version;
    public string $title;
    public string $description;
    public bool $enabled;
    private bool $_check;
	  public string $development_status; // '' = production ready, 'd' = in development, '' = Idee/Konzept

    public function __construct() {
      $this->code        = 'bx_security_monitor';
      $this->version     = '1.1.0';
      $this->title       = MODULE_BX_SECURITY_MONITOR_STATUS_TITLE;
      $this->description = MODULE_BX_SECURITY_MONITOR_STATUS_DESC;
      $this->enabled     = ((defined('MODULE_BX_SECURITY_MONITOR_STATUS') && MODULE_BX_SECURITY_MONITOR_STATUS == 'True') ? true : false);
      $this->development_status = '';
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

    }

    public function remove(): void {
      xtc_db_query("DELETE FROM " . TABLE_CONFIGURATION . " WHERE configuration_key IN ('" . implode("', '", $this->keys()) . "')");
      xtc_db_query("DELETE FROM " . TABLE_CONFIGURATION . " WHERE configuration_key IN ('" . implode("', '", $this->keys2()) . "')");
      xtc_db_query("DELETE FROM " . TABLE_CONFIGURATION_GROUP . " WHERE configuration_group_title = 'BX Security Monitor'");

      xtc_db_query("DROP TABLE IF EXISTS `msec_blocks`");
      xtc_db_query("DROP TABLE IF EXISTS `msec_events`");
      xtc_db_query("DROP TABLE IF EXISTS `msec_whitelist`");
      xtc_db_query("DROP TABLE IF EXISTS `msec_admin_sessions`");
      xtc_db_query("DROP TABLE IF EXISTS `msec_manual_rules`");

      xtc_db_query("ALTER TABLE " . TABLE_ADMIN_ACCESS . " DROP COLUMN bx_security_monitor");
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
        
      // Dateien definieren
      $dirs_and_files   = array();

      $dirs_and_files[] = DIR_FS_ADMIN . 'bx_security_monitor.php';
      $dirs_and_files[] = DIR_FS_ADMIN . 'images/icons/heading/bx-security-monitor.png';
      $dirs_and_files[] = DIR_FS_ADMIN . 'includes/extra/css/bx_security_monitor.php';
      $dirs_and_files[] = DIR_FS_ADMIN . 'includes/extra/filenames/bx_security_monitor.php';
      $dirs_and_files[] = DIR_FS_ADMIN . 'includes/extra/functions/bx_security_monitor.php';
      $dirs_and_files[] = DIR_FS_ADMIN . 'includes/extra/javascript/bx_security_monitor.php';
      $dirs_and_files[] = DIR_FS_ADMIN . 'includes/extra/menu/bx_security_monitor.php';
      
      $dirs_and_files[] = DIR_FS_CATALOG . 'includes/extra/application_top/application_top_begin/bx_security_bootstrap.php';
      $dirs_and_files[] = DIR_FS_CATALOG . 'includes/modules/bx_admin_login_guard.php';
      $dirs_and_files[] = DIR_FS_CATALOG . 'includes/modules/bx_guard.php';
      $dirs_and_files[] = DIR_FS_CATALOG . 'lang/english/extra/admin/bx_security_monitor.php';
      $dirs_and_files[] = DIR_FS_CATALOG . 'lang/english/modules/system/bx_security_monitor.php';
      $dirs_and_files[] = DIR_FS_CATALOG . 'lang/german/extra/admin/bx_security_monitor.php';
      $dirs_and_files[] = DIR_FS_CATALOG . 'lang/german/modules/system/bx_security_monitor.php';

      // Dateien löschen
      foreach ($dirs_and_files as $dir_or_file) {
        if (!$this->secureDelete($dir_or_file)) {
          $messageStack->add_session($dir_or_file.MODULE_BX_SECURITY_MONITOR_TEXT_COULD_NOT_BE_DELETED, 'error');
          $result = false;
        }
      }
        
      if ($result === true) {
        $messageStack->add_session(MODULE_BX_SECURITY_MONITOR_TEXT_SUCCESSFULLY_REMOVED, 'success');
      } else {
        $messageStack->add_session(MODULE_BX_SECURITY_MONITOR_TEXT_REMOVAL_INCOMPLETE, 'error');
      }
        
      // Datei selbst löschen
      $this->secureDelete(DIR_FS_ADMIN.'includes/modules/system/bx_security_monitor.php');

      xtc_redirect(xtc_href_link(FILENAME_MODULE_EXPORT, 'set=system'));
    }

    private function secureDelete(string $path): bool {
      // 1. Existiert der Pfad überhaupt?
      if (!file_exists($path)) {
        return true;
      }

      // --- SICHERHEITS-CHECK ---
      // Holt den echten, bereinigten Pfad (löst relative Teile auf)
      $realPath  = realpath($path);
      $adminRoot = realpath(DIR_FS_ADMIN);

      // Sicherheitsregel A: Pfad darf nicht leer sein
      if (empty($realPath) || empty($adminRoot)) {
        return false;
      }

      // Sicherheitsregel B: Wenn der Pfad EXAKT dein Admin-Hauptordner 
      // oder das Hauptverzeichnis (/) ist -> SOFORT ABBRECHEN!
      if ($realPath === $adminRoot || $realPath === DIRECTORY_SEPARATOR) {
        return false; 
      }
      // -----------------------------------

      if (!is_writable($realPath)) {
        return false;
      }

      // Wenn es eine Datei oder ein Symlink ist -> nur diese löschen und beenden!
      if (!is_dir($realPath) || is_link($realPath)) {
        return unlink($realPath);
      }

      // Nur wenn es ein Ordner ist, wird tiefer gegangen
      try {
        $iterator = new RecursiveIteratorIterator(
          new RecursiveDirectoryIterator($realPath, FilesystemIterator::SKIP_DOTS),
          RecursiveIteratorIterator::CHILD_FIRST
        );

        foreach ($iterator as $item) {
          $itemPath = $item->getRealPath();

          if (!is_writable($itemPath)) {
            return false;
          }
          
          if ($item->isDir() && !$item->isLink()) {
            if (!rmdir($itemPath)) {
              return false;
            }
          } else {
            if (!unlink($itemPath)) {
              return false;
            }
          }
        }
      } catch (UnexpectedValueException $e) {
        return false;
      }

      return rmdir($realPath);
    }
  }
