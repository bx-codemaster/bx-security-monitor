<?php
/* ---------------------------------------------------------
   $Id: bx_security_monitor.php 00000 2026-11-27 00:00:00Z benax $

   modified eCommerce Shopsoftware
   http://www.modified-shop.org

   Copyright (c) 2009 - 2013 [www.modified-shop.org]
   ---------------------------------------------------------

   Released under the GNU General Public License
   -------------------------------------------------------*/

defined('_VALID_XTC') or die('Direct Access to this location is not allowed.');

class bx_security_monitor {
    public string $code;
    public string $title;
    public string $description;
    public int $sort_order;
    public bool $enabled;
    private bool $_check;
    public string $development_status;
    public string $version;
    public array $properties = [];
    private ?BxGithubModuleUpdater $githubUpdater = null;
    private ?array $updateStatus = null;

    // Spalte in admin_access
    private const ACCESS_COLUMN = 'bx_security_monitor';

    // Tabellen in Lösch-Reihenfolge (abhängige zuerst)
    private const TABLES = ['msec_manual_rules', 'msec_admin_sessions', 'msec_whitelist', 'msec_events', 'msec_blocks'];

    public function __construct() {
        // Bootstrap-Logik für Übergangsphase: zentraler Updater bevorzugt, eigene Kopie nur als Fallback
        if (!class_exists(BxGithubModuleUpdater::class)) {
            $bootstrapPath = DIR_FS_ADMIN . 'includes/classes/BX/Github/BxGithubModuleUpdater.php';
            if (!is_file($bootstrapPath)) {
                throw new RuntimeException('bx-module-updater ist nicht installiert.');
            }
            require_once $bootstrapPath;
        } elseif (
            defined(BxGithubModuleUpdater::class . '::VERSION')
            && version_compare(BxGithubModuleUpdater::VERSION, '1.1.0', '>')
        ) {
            // Zentrale Version ist neuer -> eigene Kopie NICHT laden
        } else {
            require_once DIR_FS_ADMIN . 'includes/classes/BX/Github/BxGithubModuleUpdater.php';
        }

        $migrationFile = DIR_FS_ADMIN . 'includes/classes/BX/Github/BxSecurityMonitorMigrations.php';
        if (is_file($migrationFile)) {
            require_once $migrationFile;
        }

        $this->code = 'bx_security_monitor';
        $this->title = MODULE_BX_SECURITY_MONITOR_STATUS_TITLE;
        $this->description = MODULE_BX_SECURITY_MONITOR_STATUS_DESC;
        $this->sort_order = defined('MODULE_BX_SECURITY_MONITOR_SORT_ORDER') ? (int)MODULE_BX_SECURITY_MONITOR_SORT_ORDER : 0;
        $this->enabled = (defined('MODULE_BX_SECURITY_MONITOR_STATUS') && MODULE_BX_SECURITY_MONITOR_STATUS == 'True');
        $this->development_status = 'p';
        $this->version = '1.6.0';

        if (
            defined('MODULE_BX_SECURITY_MONITOR_VERSION')
            && class_exists(BxSecurityMonitorMigrations::class)
        ) {
            try {
                BxSecurityMonitorMigrations::migratePending();
            } catch (Throwable $migrationException) {
                global $messageStack;
                if (isset($messageStack) && is_object($messageStack)) {
                    $messageStack->add_session(
                        'BX Security Monitor Datenbankmigration fehlgeschlagen: '
                        . htmlspecialchars($migrationException->getMessage(), ENT_QUOTES, 'UTF-8'),
                        'error'
                    );
                }
            }
        } elseif (defined('MODULE_BX_SECURITY_MONITOR_VERSION')) {
            global $messageStack;
            if (isset($messageStack) && is_object($messageStack)) {
                $messageStack->add_session(
                    'BX Security Monitor Migrationsklasse fehlt. Keine Datenbankmigration wurde ausgeführt.',
                    'error'
                );
            }
        }

        if (defined('MODULE_BX_SECURITY_MONITOR_VERSION')) {
            $this->updateStatus = $this->getGithubUpdater()->checkForUpdate(
                ($_GET['bx_updater_refresh'] ?? '') === '1'
            );
            $this->properties['button_update'] = $this->createRefreshButton();
            if (
                $this->updateStatus['has_update']
                && !empty($this->updateStatus['zip_url'])
                && !empty($this->updateStatus['sha256'])
            ) {
                $this->properties['button_update'] = $this->createUpdateButton(
                    $this->updateStatus['latest_version'],
                    true
                ) . $this->properties['button_update'];
            }
        }
    }

    public function process($file): void {
        if (($_POST['bx_updater_action'] ?? '') === 'install') {
            global $messageStack;
            $result = $this->getGithubUpdater()->installLatestUpdate();
            $messageStack->add_session($result['message'], $result['ok'] ? 'success' : 'error');
            xtc_redirect(xtc_href_link(
                FILENAME_MODULE_EXPORT,
                'set=system&module=' . $this->code . '&action=edit'
            ));
        }
    }

    public function display(): array {
        $txt = $this->createUpdateNotice() . '<div style="text-align: center;">' .
            xtc_button(BUTTON_SAVE) .
            xtc_button_link(BUTTON_CANCEL, xtc_href_link(FILENAME_MODULE_EXPORT, 'set=' . $_GET['set'] . '&module=' . $this->code)) .
            '</div>';
        return ['text' => $txt];
    }

    public function check(): bool {
        if (!isset($this->_check)) {
            $check_query = xtc_db_query("SELECT configuration_value
                                         FROM " . TABLE_CONFIGURATION . "
                                         WHERE configuration_key = 'MODULE_BX_SECURITY_MONITOR_STATUS'");
            $this->_check = xtc_db_num_rows($check_query) > 0;
        }
        return $this->_check;
    }

    public function install(): void {
        xtc_db_query("ALTER TABLE " . TABLE_ADMIN_ACCESS . " ADD bx_security_monitor INTEGER(1)");
        xtc_db_query("UPDATE " . TABLE_ADMIN_ACCESS . " SET bx_security_monitor = 1");

        $freeId_query = xtc_db_query("SELECT MIN(configuration_group_id+1) AS id
                                      FROM " . TABLE_CONFIGURATION_GROUP . "
                                     WHERE (configuration_group_id+1) NOT IN
                                       (SELECT configuration_group_id FROM " . TABLE_CONFIGURATION_GROUP . " WHERE configuration_group_id IS NOT NULL)");
        $freeId = xtc_db_fetch_array($freeId_query);

        $freeSort_query = xtc_db_query("SELECT MIN(sort_order+1) AS sort_order
                                        FROM " . TABLE_CONFIGURATION_GROUP . "
                                       WHERE (sort_order+1) NOT IN (SELECT sort_order FROM " . TABLE_CONFIGURATION_GROUP . " WHERE sort_order IS NOT NULL)");
        $freeSort = xtc_db_fetch_array($freeSort_query);
        $group_id = (int)$freeId['id'];

        xtc_db_query("INSERT INTO " . TABLE_CONFIGURATION_GROUP . " (configuration_group_id, configuration_group_title, configuration_group_description, sort_order, visible)
                      VALUES ('" . (int)$group_id . "',
                              '" . xtc_db_input('BX Security Monitor') . "',
                              '" . xtc_db_input('Settings for the BX Security Monitor module') . "',
                              '" . (int)$freeSort['sort_order'] . "',
                              1 )");

        $configs = [
            ['MODULE_BX_SECURITY_MONITOR_STATUS', 'True', 6, 1, "xtc_cfg_select_option(array('True', 'False'), "],
            ['MODULE_BX_SECURITY_MONITOR_VERSION', $this->version, 6, 2, ''],
            ['MODULE_BX_SECURITY_MONITOR_CONFIG_GROUP_ID', (string)$group_id, 6, 3, 'bx_configuration_field_version('],
            ['MODULE_BX_SECURITY_SCANNER_STATUS', 'True', $group_id, 1, "xtc_cfg_select_option(array('True', 'False'), "],
            ['MODULE_BX_SECURITY_BLOCK_THRESHOLD', '25', $group_id, 2, ''],
            ['MODULE_BX_SECURITY_SCORE_WINDOW_MINUTES', '10', $group_id, 3, ''],
            ['MODULE_BX_SECURITY_BLOCK_HOURS', '24', $group_id, 4, ''],
            ['MODULE_BX_SECURITY_EVENT_RETENTION_DAYS', '14', $group_id, 5, ''],
            ['MODULE_BX_SECURITY_ADMIN_LOGIN_STATUS', 'True', $group_id, 6, "xtc_cfg_select_option(array('True', 'False'), "],
            ['MODULE_BX_SECURITY_ADMIN_LOGIN_MAX_ATTEMPTS', '10', $group_id, 7, ''],
            ['MODULE_BX_SECURITY_ADMIN_LOGIN_WINDOW_MINUTES', '15', $group_id, 8, ''],
            ['MODULE_BX_SECURITY_ADMIN_LOGIN_BLOCK_MINUTES', '60', $group_id, 9, ''],
            ['MODULE_BX_SECURITY_EVENT_RETENTION_DAYS', '14', $group_id, 10, ''],
            ['MODULE_BX_SECURITY_ADMIN_LOGIN_STATUS', 'True', $group_id, 11, "xtc_cfg_select_option(array('True', 'False'), "],
            ['MODULE_BX_SECURITY_ADMIN_LOGIN_MAX_ATTEMPTS', '10', $group_id, 12, ''],
            ['MODULE_BX_SECURITY_ADMIN_LOGIN_WINDOW_MINUTES', '15', $group_id, 13, ''],
            ['MODULE_BX_SECURITY_ADMIN_LOGIN_BLOCK_MINUTES', '60', $group_id, 14, ''],
            ['MODULE_BX_SECURITY_MANUAL_RULES_CACHE', '', $group_id, 15, ''],
        ];

        foreach ($configs as $i => $c) {
            xtc_db_query("INSERT INTO " . TABLE_CONFIGURATION . "
                          (configuration_key, configuration_value, configuration_group_id, sort_order, date_added, set_function)
                          VALUES ('" . xtc_db_input($c[0]) . "', '" . xtc_db_input($c[1]) . "', " . (int)$c[2] . ", " . (int)$c[3] . ", NOW(), '" . xtc_db_input($c[4]) . "')");
        }

        // Schema-Version setzen
        $schemaSortQuery = xtc_db_query(
            "SELECT COALESCE(MAX(sort_order), 0) AS max_sort_order
             FROM " . TABLE_CONFIGURATION . "
             WHERE configuration_group_id = " . (int)$group_id
        );
        $schemaSort = $schemaSortQuery ? xtc_db_fetch_array($schemaSortQuery) : [];
        $schemaSortOrder = ((int)($schemaSort['max_sort_order'] ?? 0)) + 1;

        xtc_db_query("INSERT INTO " . TABLE_CONFIGURATION . "
                      (configuration_key, configuration_value, configuration_group_id, sort_order, date_added)
                      VALUES (
                        'MODULE_BX_SECURITY_MONITOR_SCHEMA_VERSION',
                        '1.6.0',
                        " . (int)$group_id . ",
                        " . $schemaSortOrder . ",
                        NOW()
                      )");

        // Tabellen
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
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

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
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

        xtc_db_query("CREATE TABLE IF NOT EXISTS msec_whitelist (
            whitelist_id INT(11) NOT NULL AUTO_INCREMENT,
            ip_address VARCHAR(45) NOT NULL,
            note VARCHAR(255) NOT NULL DEFAULT '',
            date_added DATETIME NOT NULL,
            PRIMARY KEY (whitelist_id),
            UNIQUE KEY ip_address (ip_address)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

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
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

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
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
    }

    public function remove(): void {
        xtc_db_query("DELETE FROM " . TABLE_CONFIGURATION . " WHERE configuration_key IN ('" . implode("', '", $this->keys()) . "')");
        xtc_db_query("DELETE FROM " . TABLE_CONFIGURATION . " WHERE configuration_key = 'MODULE_BX_SECURITY_MONITOR_SCHEMA_VERSION'");
        xtc_db_query("DELETE FROM " . TABLE_CONFIGURATION_GROUP . " WHERE configuration_group_title = 'BX Security Monitor'");
        xtc_db_query("ALTER TABLE " . TABLE_ADMIN_ACCESS . " DROP COLUMN bx_security_monitor");
        foreach (self::TABLES as $table) {
            xtc_db_query("DROP TABLE IF EXISTS " . $table);
        }
    }

    public function keys(): array {
        return ['MODULE_BX_SECURITY_MONITOR_STATUS', 'MODULE_BX_SECURITY_MONITOR_VERSION', 'MODULE_BX_SECURITY_MONITOR_CONFIG_GROUP_ID'];
    }

    public function keys2(): array {
        return [
            'MODULE_BX_SECURITY_SCANNER_STATUS',
            'MODULE_BX_SECURITY_BLOCK_THRESHOLD',
            'MODULE_BX_SECURITY_SCORE_WINDOW_MINUTES',
            'MODULE_BX_SECURITY_BLOCK_HOURS',
            'MODULE_BX_SECURITY_EVENT_RETENTION_DAYS',
            'MODULE_BX_SECURITY_ADMIN_LOGIN_STATUS',
            'MODULE_BX_SECURITY_ADMIN_LOGIN_MAX_ATTEMPTS',
            'MODULE_BX_SECURITY_ADMIN_LOGIN_WINDOW_MINUTES',
            'MODULE_BX_SECURITY_ADMIN_LOGIN_BLOCK_MINUTES',
            'MODULE_BX_SECURITY_EVENT_RETENTION_DAYS',
            'MODULE_BX_SECURITY_ADMIN_LOGIN_STATUS',
            'MODULE_BX_SECURITY_ADMIN_LOGIN_MAX_ATTEMPTS',
            'MODULE_BX_SECURITY_ADMIN_LOGIN_WINDOW_MINUTES',
            'MODULE_BX_SECURITY_ADMIN_LOGIN_BLOCK_MINUTES',
            'MODULE_BX_SECURITY_MANUAL_RULES_CACHE',
        ];
    }

    public function custom(): void {
        if (($_POST['bx_updater_action'] ?? '') === 'install') {
            global $messageStack;
            $result = $this->getGithubUpdater()->installLatestUpdate();
            $messageStack->add_session($result['message'], $result['ok'] ? 'success' : 'error');
            return;
        }

        if (($_GET['delete'] ?? '') !== 'true') {
            return;
        }

        global $messageStack;
        $result = true;
        $dirs_and_files = [
            DIR_FS_ADMIN . 'images/icons/heading/bx-security-monitor.png',
            DIR_FS_ADMIN . 'includes/extra/menu/bx_security_monitor.php',
            DIR_FS_ADMIN . 'includes/extra/filenames/bx_security_monitor.php',
            DIR_FS_ADMIN . 'includes/extra/javascript/bx_security_monitor.php',
            DIR_FS_ADMIN . 'includes/classes/BX/Github/BxSecurityMonitorMigrations.php',
            DIR_FS_CATALOG . 'cache/bx_github_updater/bx-security-monitor',
            DIR_FS_CATALOG . 'lang/english/extra/admin/bx_security_monitor.php',
            DIR_FS_CATALOG . 'lang/german/extra/admin/bx_security_monitor.php',
            DIR_FS_CATALOG . 'lang/english/modules/system/bx_security_monitor.php',
            DIR_FS_CATALOG . 'lang/german/modules/system/bx_security_monitor.php',
        ];

        foreach ($dirs_and_files as $dir_or_file) {
            if (!$this->secureDelete($dir_or_file)) {
                $messageStack->add_session($dir_or_file . ' konnte nicht gelöscht werden.', 'error');
                $result = false;
            }
        }

        if ($result === true) {
            $messageStack->add_session('BX Security Monitor erfolgreich entfernt.', 'success');
        } else {
            $messageStack->add_session('Entfernung unvollständig.', 'error');
        }

        $this->secureDelete(DIR_FS_ADMIN . 'includes/modules/system/bx_security_monitor.php');
        xtc_redirect(xtc_href_link(FILENAME_MODULE_EXPORT, 'set=system'));
    }

    private function getGithubUpdater(): BxGithubModuleUpdater {
        if ($this->githubUpdater === null) {
            $this->githubUpdater = new BxGithubModuleUpdater([
                'owner' => 'bx-codemaster',
                'repo' => 'bx-security-monitor',
                'module_name' => 'bx-security-monitor',
                'module_prefix' => 'BX_SECURITY_MONITOR',
                'admin_dir' => DIR_ADMIN,
                'public_key' => 't29LsiqUgqhsOM+mE+DCTUsd4Xu8Nmja3lR6NUKJnto=',
                'allowed_paths' => [
                    'admin/includes/extra/menu',
                    'admin/includes/extra/filenames',
                    'admin/includes/extra/javascript',
                    'admin/includes/modules/system',
                    'admin/images/icons/heading',
                    'lang/english/extra/admin',
                    'lang/german/extra/admin',
                    'lang/english/modules/system',
                    'lang/german/modules/system',
                ],
                'current_version' => version_compare(
                    $this->version,
                    MODULE_BX_SECURITY_MONITOR_VERSION,
                    '>'
                ) ? $this->version : MODULE_BX_SECURITY_MONITOR_VERSION,
            ]);
        }
        return $this->githubUpdater;
    }

    private function createUpdateButton(string $version, bool $standaloneForm): string {
        $formStart = '';
        $formEnd = '';
        $actionField = ' name="bx_updater_action" value="install"';
        if ($standaloneForm) {
            $formStart = xtc_draw_form('bx_security_monitor_update', FILENAME_MODULE_EXPORT, 'set=system&module=' . $this->code . '&action=custom');
            $formEnd = '</form>';
            $actionField = '';
        }
        return $formStart
            . ($standaloneForm ? xtc_draw_hidden_field('bx_updater_action', 'install') : '')
            . '<button type="submit"' . $actionField . ' class="button bx-update" onclick="return confirm(\''
            . sprintf(MODULE_BX_SECURITY_MONITOR_UPDATE_CONFIRM, htmlspecialchars($version, ENT_QUOTES, 'UTF-8'))
            . '\');">'
            . sprintf(MODULE_BX_SECURITY_MONITOR_UPDATE_BUTTON, htmlspecialchars($version, ENT_QUOTES, 'UTF-8'))
            . '</button>' . $formEnd . '<br>';
    }

    private function createRefreshButton(): string {
        $label = defined('MODULE_BX_SECURITY_MONITOR_UPDATE_CHECK')
            ? MODULE_BX_SECURITY_MONITOR_UPDATE_CHECK
            : 'Jetzt prüfen';
        return '<a class="button btnbox" href="'
            . xtc_href_link(FILENAME_MODULE_EXPORT, xtc_get_all_get_params(['bx_updater_refresh']) . 'bx_updater_refresh=1')
            . '" style="width: auto; display: inline-block;">' . htmlspecialchars($label, ENT_QUOTES, 'UTF-8') . '</a>';
    }

    private function createUpdateNotice(): string {
        $refreshLink = $this->createRefreshButton();
        if ($this->updateStatus === null || !$this->updateStatus['has_update'] || empty($this->updateStatus['latest_version'])) {
            return '<div class="messageStackInfo txta-c">' . $refreshLink . '</div>';
        }
        return '<div class="messageStackWarning txta-c">'
            . sprintf(MODULE_BX_SECURITY_MONITOR_UPDATE_AVAILABLE, htmlspecialchars($this->updateStatus['latest_version'], ENT_QUOTES, 'UTF-8'))
            . '<br>'
            . (!empty($this->updateStatus['zip_url']) && !empty($this->updateStatus['sha256'])
                ? $this->createUpdateButton($this->updateStatus['latest_version'], false)
                : ' ' . MODULE_BX_SECURITY_MONITOR_UPDATE_NOT_INSTALLABLE)
            . $refreshLink
            . '</div>';
    }

    private function secureDelete(string $path): bool {
        if (!file_exists($path)) return true;
        $realPath = realpath($path);
        $adminRoot = realpath(DIR_FS_ADMIN);
        if (empty($realPath) || empty($adminRoot)) return false;
        if ($realPath === $adminRoot || $realPath === DIRECTORY_SEPARATOR) return false;
        if (!is_writable($realPath)) return false;
        if (!is_dir($realPath) || is_link($realPath)) return unlink($realPath);
        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($realPath, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::CHILD_FIRST
            );
            foreach ($iterator as $item) {
                $itemPath = $item->getRealPath();
                if (!is_writable($itemPath)) return false;
                if ($item->isDir() && !$item->isLink()) {
                    if (!rmdir($itemPath)) return false;
                } else {
                    if (!unlink($itemPath)) return false;
                }
            }
        } catch (UnexpectedValueException) {
            return false;
        }
        return rmdir($realPath);
    }
}
