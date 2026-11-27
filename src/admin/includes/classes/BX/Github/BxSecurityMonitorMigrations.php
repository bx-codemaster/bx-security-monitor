<?php

declare(strict_types=1);

require_once DIR_FS_ADMIN . 'includes/classes/BX/Github/BxModuleMigration.php';

final class BxSecurityMonitorMigrations extends BxModuleMigration
{
    public const SCHEMA_VERSION = '1.6.0';
    public const STORED_SCHEMA_KEY = 'MODULE_BX_SECURITY_MONITOR_SCHEMA_VERSION';
    private const FAILURE_CACHE_SECONDS = 300;
    private const MIGRATION_LOCK_SECONDS = 10;

    public static function migratePending(): void {
        if (!self::shouldAttemptMigration()) {
            $failure = self::readFailure();
            if ($failure !== null) {
                throw new RuntimeException(
                    'Die letzte Migration ist fehlgeschlagen. Wiederholung frühestens in '
                    . max(0, self::FAILURE_CACHE_SECONDS - (time() - (int)$failure['time']))
                    . ' Sekunden: ' . (string)$failure['error']
                );
            }
            return;
        }
        if (!self::acquireMigrationLock()) return;
        try {
            self::migratePendingUnlocked();
            self::removeFailureMarker();
        } catch (Throwable $e) {
            self::recordFailure($e);
            throw $e;
        } finally {
            self::releaseMigrationLock();
        }
    }

    private static function migratePendingUnlocked(): void {
        $storedVersion = self::readStoredSchemaVersion();
        if (version_compare($storedVersion, self::SCHEMA_VERSION, '>=')) return;
        self::migrate($storedVersion, self::SCHEMA_VERSION);
        self::writeStoredSchemaVersion(self::SCHEMA_VERSION);
    }

    public static function migrate(string $from, string $to): void {
        self::migrateTo160($from, $to);
    }

    private static function migrateTo160(string $from, string $to): void {
        if (!self::crossesVersion($from, $to, '1.6.0')) return;

        // Admin-Access Spalte
        if (!self::columnExists(TABLE_ADMIN_ACCESS, 'bx_security_monitor')) {
            xtc_db_query(
                'ALTER TABLE ' . self::quoteIdentifier(TABLE_ADMIN_ACCESS)
                . ' ADD COLUMN `bx_security_monitor` INTEGER(1) NOT NULL DEFAULT 1'
            );
        }

        // Tabellen prüfen (falls nicht durch install() angelegt)
        if (!self::tableExists('msec_blocks')) {
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
        }
        if (!self::tableExists('msec_events')) {
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
        }
        if (!self::tableExists('msec_whitelist')) {
            xtc_db_query("CREATE TABLE IF NOT EXISTS msec_whitelist (
                whitelist_id INT(11) NOT NULL AUTO_INCREMENT,
                ip_address VARCHAR(45) NOT NULL,
                note VARCHAR(255) NOT NULL DEFAULT '',
                date_added DATETIME NOT NULL,
                PRIMARY KEY (whitelist_id),
                UNIQUE KEY ip_address (ip_address)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
        }
        if (!self::tableExists('msec_admin_sessions')) {
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
        }
        if (!self::tableExists('msec_manual_rules')) {
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
    }

    private static function readStoredSchemaVersion(): string {
        $query = xtc_db_query(
            "SELECT configuration_value
             FROM " . TABLE_CONFIGURATION . "
             WHERE configuration_key = '" . xtc_db_input(self::STORED_SCHEMA_KEY) . "'
             LIMIT 1"
        );
        if (!$query || xtc_db_num_rows($query) < 1) return '0.0.0';
        $row = xtc_db_fetch_array($query);
        $version = trim((string)($row['configuration_value'] ?? ''));
        return $version !== '' ? $version : '0.0.0';
    }

    private static function writeStoredSchemaVersion(string $version): void {
        $query = xtc_db_query(
            "SELECT configuration_id
             FROM " . TABLE_CONFIGURATION . "
             WHERE configuration_key = '" . xtc_db_input(self::STORED_SCHEMA_KEY) . "'
             LIMIT 1"
        );
        if ($query && xtc_db_num_rows($query) > 0) {
            $result = xtc_db_query(
                "UPDATE " . TABLE_CONFIGURATION . "
                 SET configuration_value = '" . xtc_db_input($version) . "',
                     last_modified = NOW()
                 WHERE configuration_key = '" . xtc_db_input(self::STORED_SCHEMA_KEY) . "'"
            );
            if ($result === false) throw new RuntimeException('Der gespeicherte Schemaschritt konnte nicht aktualisiert werden.');
            return;
        }
        $groupId = self::findConfigurationGroupId();
        $sortOrder = self::nextConfigurationSortOrder($groupId);
        $result = xtc_db_query(
            "INSERT INTO " . TABLE_CONFIGURATION . "
             (configuration_key, configuration_value, configuration_group_id, sort_order, date_added)
             VALUES (
                '" . xtc_db_input(self::STORED_SCHEMA_KEY) . "',
                '" . xtc_db_input($version) . "',
                " . $groupId . ",
                " . $sortOrder . ",
                NOW()
             )"
        );
        if ($result === false) throw new RuntimeException('Der gespeicherte Schemaschritt konnte nicht angelegt werden.');
    }

    private static function findConfigurationGroupId(): int {
        foreach (['MODULE_BX_SECURITY_MONITOR_CONFIG_GROUP_ID', 'MODULE_BX_SECURITY_MONITOR_STATUS'] as $key) {
            $query = xtc_db_query(
                "SELECT configuration_value, configuration_group_id
                 FROM " . TABLE_CONFIGURATION . "
                 WHERE configuration_key = '" . xtc_db_input($key) . "'
                 LIMIT 1"
            );
            if (!$query || xtc_db_num_rows($query) < 1) continue;
            $row = xtc_db_fetch_array($query);
            $value = $key === 'MODULE_BX_SECURITY_MONITOR_CONFIG_GROUP_ID'
                ? ($row['configuration_value'] ?? '')
                : ($row['configuration_group_id'] ?? '');
            if ((int)$value > 0) return (int)$value;
        }
        throw new RuntimeException('Die Modul-Konfigurationsgruppe konnte nicht ermittelt werden.');
    }

    private static function acquireMigrationLock(): bool {
        $query = xtc_db_query(
            "SELECT GET_LOCK('bx_security_monitor_migration', " . self::MIGRATION_LOCK_SECONDS . ") AS acquired"
        );
        $row = $query ? xtc_db_fetch_array($query) : [];
        return (int)($row['acquired'] ?? 0) === 1;
    }

    private static function releaseMigrationLock(): void {
        xtc_db_query("SELECT RELEASE_LOCK('bx_security_monitor_migration')");
    }

    private static function shouldAttemptMigration(): bool {
        $path = self::failureMarkerPath();
        if (!is_file($path)) return true;
        return time() - (int)filemtime($path) >= self::FAILURE_CACHE_SECONDS;
    }

    private static function recordFailure(Throwable $e): void {
        $path = self::failureMarkerPath();
        $dir = dirname($path);
        if (!is_dir($dir)) @mkdir($dir, 0700, true);
        @file_put_contents($path, json_encode(['time' => time(), 'error' => $e->getMessage()], JSON_UNESCAPED_UNICODE), LOCK_EX);
    }

    private static function removeFailureMarker(): void {
        $path = self::failureMarkerPath();
        if (is_file($path)) @unlink($path);
    }

    private static function readFailure(): ?array {
        $path = self::failureMarkerPath();
        if (!is_file($path)) return null;
        $data = json_decode((string)file_get_contents($path), true);
        if (!is_array($data) || !isset($data['time'], $data['error'])) return null;
        return ['time' => (int)$data['time'], 'error' => (string)$data['error']];
    }

    private static function failureMarkerPath(): string {
        return rtrim(DIR_FS_CATALOG, '/\\') . '/cache/bx_github_updater/bx-security-monitor/migration-error.json';
    }
}
