<?php
/**
 * Deutsche Sprachdatei für das Systemmodul bx_security_monitor.
 * /lang/german/modules/system/bx_security_monitor.php
 *
 * Diese Datei definiert die deutschen Modultexte für die Konfiguration,
 * Installationshinweise und Fehlermeldungen im modified-Adminbereich.
 *
 * @file        bx_security_monitor.php
 * @package     bx-security-monitor
 * @author      bx-codemaster (benax)
 * @website     www.bx-coding.de
 * @license     GNU General Public License (GPL)
 * @since       2026-07-10
 */
                    
define('MODULE_BX_SECURITY_MONITOR_STATUS_TITLE', 'BX Security Monitor - <span style="font-weight: normal;">Sicherheitsüberwachung</span>');

$description = '
<details class="bxac-card">
	<summary class="bxac-summary" style="list-style: none; display: inline-flex; align-items: center; gap: 8px; width: 100%;">
    <span class="bxac-arrow" style="font-size: 2rem;">▸</span>
    <span class="bxac-title">' . xtc_image(DIR_WS_ICONS.'heading/bx_security_monitor.png', 'BX Security Monitor', '', '', 'style="max-height: 40px; vertical-align: middle; margin-right: 8px; cursor: pointer;"') . '<strong>BX Security Monitor</strong></span>
  </summary>
  <div class="bxac-body">
    <h3 style="margin-top: 0;">Modul zur Sicherheitsüberwachung</h3>
    <p>Überwacht sicherheitsrelevante Ereignisse im System und bietet Administrationsfunktionen zum Schutz vor unbefugtem Zugriff.</p>
		<h5>Fazit:</h5>
		<p>Das Modul bietet eine umfassende Sicherheitsüberwachung und erleichtert die Administration sicherheitsrelevanter Ereignisse im System.</p>
  </div>
</details>';

if((!defined('MODULE_BX_SECURITY_MONITOR_STATUS')) || (MODULE_BX_SECURITY_MONITOR_STATUS != 'True') && basename($_SERVER['PHP_SELF']) == 'module_export.php') {
	$description .= '<p><a class="button btnbox but_red" style="text-align:center;" onclick="return confirmLink(\'Alle Dateien löschen?\', \'\' ,this);" href="'.xtc_href_link(FILENAME_MODULE_EXPORT, 'set=system&module=bx_security_monitor&action=custom').'">Alle Moduldateien löschen</a></p>';
}

define('MODULE_BX_SECURITY_MONITOR_STATUS_DESC', $description);

define('MODULE_BX_SECURITY_SCANNER_STATUS_TITLE', 'Scanner-Erkennung');
define('MODULE_BX_SECURITY_SCANNER_STATUS_DESC', 'Scanner-Erkennung aktivieren?');

define('MODULE_BX_SECURITY_MONITOR_CONFIG_GROUP_ID_TITLE', 'Interne Konfigurationsgruppen-ID');
define('MODULE_BX_SECURITY_MONITOR_CONFIG_GROUP_ID_DESC', 'Interner technischer Wert für die Konfigurationsgruppe des Moduls. Kann nicht manuell geändert werden.');

define('MODULE_BX_SECURITY_BLOCK_THRESHOLD_TITLE', 'Blockierschwelle');
define('MODULE_BX_SECURITY_BLOCK_THRESHOLD_DESC', 'Punktzahl für eine automatische Sperre');

define('MODULE_BX_SECURITY_SCORE_WINDOW_MINUTES_TITLE', 'Bewertungszeitraum');
define('MODULE_BX_SECURITY_SCORE_WINDOW_MINUTES_DESC', 'Zeitraum für kumulierte Punkte');
define('MODULE_BX_SECURITY_BLOCK_HOURS_TITLE', 'Automatische Sperrdauer');
define('MODULE_BX_SECURITY_BLOCK_HOURS_DESC', 'Sperrdauer in Stunden');
define('MODULE_BX_SECURITY_EVENT_RETENTION_DAYS_TITLE', 'Aufbewahrung Ereignisse');
define('MODULE_BX_SECURITY_EVENT_RETENTION_DAYS_DESC', 'Aufbewahrung in Tagen');
define('MODULE_BX_SECURITY_ADMIN_LOGIN_STATUS_TITLE', 'Admin-Login-Wächter aktiv');
define('MODULE_BX_SECURITY_ADMIN_LOGIN_STATUS_DESC', 'Protokolliert und bremst Serien von Fehlversuchen');
define('MODULE_BX_SECURITY_ADMIN_LOGIN_MAX_ATTEMPTS_TITLE', 'Admin-Login Fehlversuche');
define('MODULE_BX_SECURITY_ADMIN_LOGIN_MAX_ATTEMPTS_DESC', 'Fehlversuche bis zur IP-Sperre');
define('MODULE_BX_SECURITY_ADMIN_LOGIN_WINDOW_MINUTES_TITLE', 'Admin-Login Zeitraum');
define('MODULE_BX_SECURITY_ADMIN_LOGIN_WINDOW_MINUTES_DESC', 'Auswertungszeitraum in Minuten');
define('MODULE_BX_SECURITY_ADMIN_LOGIN_BLOCK_MINUTES_TITLE', 'Admin-Login Sperrdauer');
define('MODULE_BX_SECURITY_ADMIN_LOGIN_BLOCK_MINUTES_DESC', 'IP-Sperrdauer in Minuten');
define('MODULE_BX_SECURITY_MANUAL_RULES_CACHE_TITLE', 'Regelcache');
define('MODULE_BX_SECURITY_MANUAL_RULES_CACHE_DESC', 'Automatisch erzeugter Cache manueller Regeln');

define('MODULE_BX_SECURITY_MONITOR_TEXT_COULD_NOT_BE_DELETED', 'FEHLER! Modul <strong>' . constant('MODULE_BX_SECURITY_MONITOR_STATUS_TITLE') . '</strong> konnte nicht gelöscht werden.');
define('MODULE_BX_SECURITY_MONITOR_TEXT_SUCCESSFULLY_REMOVED', 'Erfolg! Modul <strong>' . constant('MODULE_BX_SECURITY_MONITOR_STATUS_TITLE') . '</strong> wurde erfolgreich entfernt.');
define('MODULE_BX_SECURITY_MONITOR_TEXT_REMOVAL_INCOMPLETE', 'FEHLER! Modul <strong>' . constant('MODULE_BX_SECURITY_MONITOR_STATUS_TITLE') . '</strong> konnte nicht vollständig entfernt werden.');
