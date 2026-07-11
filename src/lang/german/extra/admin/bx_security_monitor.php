<?php
/**
 * Deutsche Sprachdatei für das Systemmodul bx_security_monitor.
 * /lang/german/extra/admin/bx_security_monitor.php
 *
 * Diese Datei definiert die deutschen Modultexte für die Konfiguration,
 * Installationshinweise und Fehlermeldungen im modified-Adminbereich.
 *
 * @file        bx_security_monitor.php
 * @package     bx-security-monitor
 * @author      bx-codemaster (benax)
 * @website     www.bx-coding.de
 * @license     GNU General Public License (GPL)
 * @since       2026-06-10
 */

define('BX_SECURITY_MONITOR_TITLE', 'BX Security Monitor - <span style="font-weight: normal;">Sicherheitsüberwachung</span>');
define('BX_SECURITY_MONITOR_DESCRIPTION', 'Dieses Modul überwacht sicherheitsrelevante Ereignisse im Shop und bietet Schutzmechanismen gegen Angriffe.');
define('BX_SECURITY_MONITOR_TITLE_TAG', 'BX Security Monitor - Sicherheitsüberwachung');
define('BX_SECURITY_MONITOR_TITLE_NOTE', 'Diese Seite wertet nur Sicherheitsereignisse aus. Sie überwacht oder verändert keine Shopdateien und sperrt keine Administratorkonten. Ein protokollierter Angriff ist kein Beweis für einen erfolgreichen Einbruch.');
define('BX_SECURITY_MONITOR_TXT_CURRENT_ACTIVITY', 'Aktuelle Aktivitätslage');

define('BX_SECURITY_MONITOR_SETTINGS_SAVED', 'Einstellungen wurden gespeichert.');
define('BX_SECURITY_MONITOR_RULE_SAVED', 'Regel wurde gespeichert.');
define('BX_SECURITY_MONITOR_INVALID_DELETE_RULE_CALL', 'Ungültiger Aufruf für das Löschen einer manuellen Regel.');
define('BX_SECURITY_MONITOR_INVALID_ADD_RULE_CALL', 'Ungültiger Aufruf für das Hinzufügen einer manuellen Regel.');
define('BX_SECURITY_MONITOR_RULE_ADDED', 'Regel wurde hinzugefügt.');

define('BX_SECURITY_MONITOR_BURST_FROM_IP', 'Anfragehäufung von einer IP');
define('BX_SECURITY_MONITOR_BURST_FROM_IP_TEXT', '%s: %d verdächtige Treffer in 15 Minuten');
define('BX_SECURITY_MONITOR_DISTRIBUTED_SCAN', 'Verteilter Scan auf denselben Pfad');
define('BX_SECURITY_MONITOR_DISTRIBUTED_SCAN_TEXT', '%d IPs griffen innerhalb einer Stunde auf %s zu');

define('BX_SECURITY_MONITOR_HIGH_SCANNER_ACTIVITY', 'Hohe Scanneraktivität');
define('BX_SECURITY_MONITOR_HIGH_SCANNER_ACTIVITY_NOTE', 'Mehrere oder stark gehäufte verdächtige Anfragen wurden erkannt.');
define('BX_SECURITY_MONITOR_MEDIUM_SCANNER_ACTIVITY', 'Erhöhte Aktivität');
define('BX_SECURITY_MONITOR_MEDIUM_SCANNER_ACTIVITY_NOTE', 'In letzter Zeit wurden auffällige Anfragen oder Häufungen erkannt.');
define('BX_SECURITY_MONITOR_LOW_SCANNER_ACTIVITY', 'Ruhige Lage');
define('BX_SECURITY_MONITOR_LOW_SCANNER_ACTIVITY_NOTE', 'Aktuell ist keine ungewöhnliche Häufung sichtbar.');

define('BX_SECURITY_MONITOR_INVALID_SAVE_CALL', 'Ungültiger Aufruf für das Speichern der Einstellungen.');
define('BX_SECURITY_MONITOR_RULE_DELETED', 'Regel wurde gelöscht.');
define('BX_SECURITY_MONITOR_INVALID_TOGGLE_RULE_CALL', 'Ungültiger Aufruf für das Umschalten der Regel.');
define('BX_SECURITY_MONITOR_STATUS_UPDATED', 'Status wurde aktualisiert.');
define('BX_SECURITY_MONITOR_INVALID_UNBLOCK_CALL', 'Ungültiger Aufruf für das Entsperren des Eintrags.');
define('BX_SECURITY_MONITOR_ENTRY_UNBLOCKED', 'Eintrag wurde entsperrt.');
define('BX_SECURITY_MONITOR_INVALID_ADD_WHITELIST_CALL', 'Ungültiger Aufruf für das Hinzufügen zur Whitelist.');
define('BX_SECURITY_MONITOR_LIST_UPDATED', 'Liste wurde aktualisiert.');
define('BX_SECURITY_MONITOR_INVALID_BLOCK_TO_WHITELIST_CALL', 'Ungültiger Aufruf für das Übernehmen des Eintrags in die Whitelist.');
define('BX_SECURITY_MONITOR_ENTRY_TAKEN_OVER', 'Eintrag wurde übernommen.');
define('BX_SECURITY_MONITOR_INVALID_DELETE_WHITELIST_CALL', 'Ungültiger Aufruf für das Löschen aus der Whitelist.');
define('BX_SECURITY_MONITOR_WHITELIST_ENTRY_DELETED', 'Whitelist-Eintrag wurde gelöscht.');
define('BX_SECURITY_MONITOR_INVALID_CLEAR_EVENTS_CALL', 'Ungültiger Aufruf für das Löschen der Ereignisse.');
define('BX_SECURITY_MONITOR_EVENTS_CLEARED', 'Ereignisse wurden gelöscht.');
define('BX_SECURITY_MONITOR_INVALID_CLEAR_EXPIRED_CALL', 'Ungültiger Aufruf für das Löschen abgelaufener Sperren.');
define('BX_SECURITY_MONITOR_EXPIRED_BLOCKS_CLEARED', 'Abgelaufene Sperren wurden gelöscht.');

define('BX_SECURITY_MONITOR_HITS_10_MIN', 'Treffer 10 Min.');
define('BX_SECURITY_MONITOR_HITS_1_HOUR', 'Treffer 1 Std.');
define('BX_SECURITY_MONITOR_HITS_24_HOURS', 'Treffer 24 Std.');
define('BX_SECURITY_MONITOR_IPS_24_HOURS', 'IP-Adressen 24 Std.');
define('BX_SECURITY_MONITOR_BLOCKED_EVENTS', 'Blockierte Ereignisse');
define('BX_SECURITY_MONITOR_ACTIVE_IP_BLOCKS', 'Aktive IP-Sperren');
define('BX_SECURITY_MONITOR_UNUSUAL_ACTIVITY', 'Ungewöhnliche Aktivität');
define('BX_SECURITY_MONITOR_NO_UNUSUAL_ACTIVITY', 'Keine ungewöhnliche Häufung in den ausgewerteten Zeitfenstern.');
define('BX_SECURITY_MONITOR_DETECTED_ATTACK_TYPES_24_HOURS', 'Erkannte Angriffsarten – 24 Stunden');
define('BX_SECURITY_MONITOR_NO_EVENTS', 'Keine Ereignisse.');
define('BX_SECURITY_MONITOR_ACTIVITY_OVERVIEW_24_HOURS', 'Aktivitätsverlauf – 24 Stunden');
define('BX_SECURITY_MONITOR_TOP_ATTACKING_IPS_24_HOURS', 'Top angreifende IPs – 24 Stunden');
define('BX_SECURITY_MONITOR_MOST_ATTACKED_PATHS_24_HOURS', 'Am häufigsten angegriffene Pfade – 24 Stunden');
define('BX_SECURITY_MONITOR_LAST_CRITICAL_OR_BLOCKED_EVENTS', 'Letzte kritische oder blockierte Ereignisse');

define('BX_SECURITY_MONITOR_TH_IP', 'IP');
define('BX_SECURITY_MONITOR_TH_HITS', 'Treffer');
define('BX_SECURITY_MONITOR_TH_SCORE', 'Punkte');
define('BX_SECURITY_MONITOR_TH_BLOCKED', 'Blockiert');
define('BX_SECURITY_MONITOR_TH_LAST_SEEN', 'Zuletzt');
define('BX_SECURITY_MONITOR_TH_PATH', 'Pfad');
define('BX_SECURITY_MONITOR_TH_REASON', 'Grund');
define('BX_SECURITY_MONITOR_TH_IPS', 'IPs');
define('BX_SECURITY_MONITOR_TH_TIME', 'Zeit');
define('BX_SECURITY_MONITOR_TH_METHOD', 'Methode');
define('BX_SECURITY_MONITOR_TH_CATEGORY', 'Kategorie');
define('BX_SECURITY_MONITOR_TH_STATUS', 'Status');
define('BX_SECURITY_MONITOR_NO_CRITICAL_EVENTS', 'Keine kritischen Ereignisse.');

define('BX_SECURITY_MONITOR_SETTINGS', 'Einstellungen');
define('BX_SECURITY_MONITOR_ACTIVE', 'aktiv');
define('BX_SECURITY_MONITOR_INACTIVE', 'deaktiviert');

define('BX_SECURITY_MONITOR_BLOCK_THRESHOLD', 'Blockierschwelle (Punkte)');
define('BX_SECURITY_MONITOR_SCORE_WINDOW_MINUTES', 'Bewertungszeitraum (Min.)');
define('BX_SECURITY_MONITOR_BLOCK_HOURS', 'Automatische Sperrdauer (Std.)');
define('BX_SECURITY_MONITOR_EVENT_RETENTION_DAYS', 'Ereignisse aufbewahren (Tage)');
define('BX_SECURITY_MONITOR_ADMIN_LOGIN_STATUS', 'Admin-Login-Wächter');
define('BX_SECURITY_MONITOR_ADMIN_LOGIN_MAX_ATTEMPTS', 'Admin-Fehlversuche bis Sperre');
define('BX_SECURITY_MONITOR_ADMIN_LOGIN_WINDOW_MINUTES', 'Admin-Auswertungszeitraum (Min.)');
define('BX_SECURITY_MONITOR_ADMIN_LOGIN_BLOCK_MINUTES', 'Admin-IP-Sperre (Min.)');
define('BX_SECURITY_MONITOR_SAVE_SETTINGS', 'Einstellungen speichern');

define('BX_SECURITY_MONITOR_MANUAL_RULES', 'Manuelle Regeln');
define('BX_SECURITY_MONITOR_MANUAL_RULES_WARNING', 'Manuelle Regeln sind mächtig. Für normale Shopseiten möglichst <strong>Präfix</strong> oder <strong>exakt</strong> verwenden. Eine zu breite Teilstring-Regel kann legitime URLs treffen.');
define('BX_SECURITY_MONITOR_PATTERN', 'Muster');
define('BX_SECURITY_MONITOR_COMPARISON', 'Vergleich');
define('BX_SECURITY_MONITOR_MATCH_PREFIX', 'Pfad beginnt mit');
define('BX_SECURITY_MONITOR_MATCH_EXACT', 'exakter Pfad');
define('BX_SECURITY_MONITOR_MATCH_CONTAINS', 'Teilstring in URL');
define('BX_SECURITY_MONITOR_ADD_RULE', 'Regel hinzuflügen');
define('BX_SECURITY_MONITOR_TH_ACTION', 'Aktion');
define('BX_SECURITY_MONITOR_NO_MANUAL_RULES', 'Keine manuellen Regeln.');
define('BX_SECURITY_MONITOR_CONFIRM_TOGGLE_RULE_STATUS', 'Regelstatus umschalten?');
define('BX_SECURITY_MONITOR_TOGGLE', 'umschalten');
define('BX_SECURITY_MONITOR_CONFIRM_DELETE_RULE', 'Regel löschen?');
define('BX_SECURITY_MONITOR_DELETE', 'löschen');

define('BX_SECURITY_MONITOR_ACTIVE_AUTO_BLOCKS', 'Aktive automatische Sperren');
define('BX_SECURITY_MONITOR_DELETE_EXPIRED_ENTRIES', 'Abgelaufene Einträge löschen');
define('BX_SECURITY_MONITOR_TH_BLOCKED_UNTIL', 'Gesperrt bis');
define('BX_SECURITY_MONITOR_NO_ACTIVE_BLOCKS', 'Keine aktiven Sperren.');
define('BX_SECURITY_MONITOR_PERMANENT', 'dauerhaft');
define('BX_SECURITY_MONITOR_UNBLOCK', 'entsperren');
define('BX_SECURITY_MONITOR_CONFIRM_BLOCK_TO_WHITELIST', 'IP entsperren und dauerhaft freigeben?');
define('BX_SECURITY_MONITOR_WHITELIST', 'Whitelist');

define('BX_SECURITY_MONITOR_PERMANENT_WHITELIST', 'Dauerhafte Whitelist');
define('BX_SECURITY_MONITOR_IP_ADDRESS', 'IP-Adresse');
define('BX_SECURITY_MONITOR_NOTE', 'Notiz');
define('BX_SECURITY_MONITOR_ADD', 'Hinzuflügen');
define('BX_SECURITY_MONITOR_ALLOW_CURRENT_ADMIN_IP', 'Aktuelle Admin-IP dauerhaft freigeben');
define('BX_SECURITY_MONITOR_TH_CREATED', 'Erstellt');
define('BX_SECURITY_MONITOR_NO_ENTRIES', 'Keine Einträge.');
define('BX_SECURITY_MONITOR_CONFIRM_DELETE_WHITELIST_ENTRY', 'Whitelist-Eintrag löschen?');

define('BX_SECURITY_MONITOR_TEMP_ADMIN_APPROVALS', 'Temporäre Admin-Freigaben');
define('BX_SECURITY_MONITOR_TEMP_ADMIN_APPROVALS_INFO', 'Erfolgreich angemeldete Admin-Sitzungen werden automatisch 30 Minuten lang freigegeben und bei jedem Adminaufruf verlängert.');
define('BX_SECURITY_MONITOR_TH_ADMIN_ID', 'Admin-ID');
define('BX_SECURITY_MONITOR_TH_EXPIRES_AT', 'läuft ab');
define('BX_SECURITY_MONITOR_NO_ACTIVE_ADMIN_APPROVALS', 'Keine aktiven Admin-Freigaben.');

define('BX_SECURITY_MONITOR_LATEST_SECURITY_EVENTS', 'Letzte Sicherheitsereignisse');
define('BX_SECURITY_MONITOR_CONFIRM_CLEAR_EVENTS', 'Alle Sicherheitsereignisse löschen? Bestehende Sperren bleiben erhalten.');
define('BX_SECURITY_MONITOR_CLEAR_EVENTS_LOG', 'Ereignisprotokoll leeren');
define('BX_SECURITY_MONITOR_TH_URL', 'URL');
define('BX_SECURITY_MONITOR_TH_USER_AGENT', 'User-Agent');
define('BX_SECURITY_MONITOR_NO_EVENTS_YET', 'Noch keine Ereignisse.');
define('BX_SECURITY_MONITOR_YES', 'ja');
define('BX_SECURITY_MONITOR_NO', 'nein');

define('BX_SECURITY_MONITOR_LOGIN_ADMIN_PHP_PATCH_MISMATCH', 'Der Core-Patch für <code>login_admin.php</code> wurde extern verändert (z.&nbsp;B. durch ein Shop-Update). Die erweiterte Login-Überwachung ist möglicherweise nicht mehr aktiv. Bitte Patch-Status prüfen.');
define('BX_SECURITY_MONITOR_LOGIN_ADMIN_PHP_TARGET_MISSING', 'Die Datei <code>login_admin.php</code> wurde nicht gefunden. Der Adminbereich könnte beeinträchtigt sein!');
define('BX_SECURITY_MONITOR_LOGIN_ADMIN_PHP_META_MISSING', 'Backup-Metadaten für <code>login_admin.php</code> fehlen. Der Patch-Status kann nicht eindeutig geprüft werden.');
define('BX_SECURITY_MONITOR_LOGIN_ADMIN_PHP_META_INVALID', 'Backup-Metadaten für <code>login_admin.php</code> sind beschädigt. Der Patch-Status kann nicht eindeutig geprüft werden.');
define('BX_SECURITY_MONITOR_LOGIN_ADMIN_PHP_NOT_INSTALLED', 'Der Patch <code>login_admin.php</code> ist nicht installiert.');
define('BX_SECURITY_MONITOR_LOGIN_ADMIN_PHP_OK', 'Der Patch-Status von <code>login_admin.php</code> ist ok.');