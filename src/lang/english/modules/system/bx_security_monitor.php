<?php
/**
 * English language file for the system module bx_security_monitor.
 * /lang/english/modules/system/bx_security_monitor.php
 *
 * This file defines the English module texts for configuration,
 * installation instructions, and error messages in the modified admin area.
 *
 * @file        bx_security_monitor.php
 * @package     bx-security-monitor
 * @author      bx-codemaster (benax)
 * @website     www.bx-coding.de
 * @license     GNU General Public License (GPL)
 * @since       2026-07-10
 */
                    
define('MODULE_BX_SECURITY_MONITOR_STATUS_TITLE', 'BX Security Monitor - <span style="font-weight: normal;">Security Monitoring</span>');

$description = '
<details class="bxac-card">
	<summary class="bxac-summary" style="list-style: none; display: inline-flex; align-items: center; gap: 8px; width: 100%;">
    <span class="bxac-arrow" style="font-size: 2rem;">▸</span>
    <span class="bxac-title">' . xtc_image(DIR_WS_ICONS.'heading/bx-security-monitor.png', 'BX Security Monitor', '', '', 'style="max-height: 40px; vertical-align: middle; margin-right: 8px; cursor: pointer;"') . '<strong>BX Security Monitor</strong></span>
  </summary>
  <div class="bxac-body">
    <h3 style="margin-top: 0;">Security Monitoring Module</h3>
    <p>Monitors security-relevant events in the system and provides administration functions to protect against unauthorized access.</p>
		<h5>Conclusion:</h5>
		<p>The module offers comprehensive security monitoring and facilitates the administration of security-relevant events in the system.</p>
  </div>
</details>';

if((!defined('MODULE_BX_SECURITY_MONITOR_STATUS')) || (MODULE_BX_SECURITY_MONITOR_STATUS != 'True') && basename($_SERVER['PHP_SELF']) == 'module_export.php') {
	$description .= '<p><a class="button btnbox but_red" style="text-align:center;" onclick="return confirmLink(\'Delete all files?\', \'\' ,this);" href="'.xtc_href_link(FILENAME_MODULE_EXPORT, 'set=system&module=bx_security_monitor&action=custom').'">Delete all module files</a></p>';
}

define('MODULE_BX_SECURITY_MONITOR_STATUS_DESC', $description);

define('MODULE_BX_SECURITY_SCANNER_STATUS_TITLE', 'Scanner Detection');
define('MODULE_BX_SECURITY_SCANNER_STATUS_DESC', 'Enable scanner detection?');

define('MODULE_BX_SECURITY_MONITOR_CONFIG_GROUP_ID_TITLE', 'Internal Configuration Group ID');
define('MODULE_BX_SECURITY_MONITOR_CONFIG_GROUP_ID_DESC', 'Internal technical value for the module\'s configuration group. Cannot be changed manually.');

define('MODULE_BX_SECURITY_BLOCK_THRESHOLD_TITLE', 'Blocking Threshold');
define('MODULE_BX_SECURITY_BLOCK_THRESHOLD_DESC', 'Score for automatic blocking');

define('MODULE_BX_SECURITY_SCORE_WINDOW_MINUTES_TITLE', 'Evaluation Period');
define('MODULE_BX_SECURITY_SCORE_WINDOW_MINUTES_DESC', 'Period for accumulated points');
define('MODULE_BX_SECURITY_BLOCK_HOURS_TITLE', 'Automatic Blocking Duration');
define('MODULE_BX_SECURITY_BLOCK_HOURS_DESC', 'Blocking duration in hours');
define('MODULE_BX_SECURITY_EVENT_RETENTION_DAYS_TITLE', 'Event Retention');
define('MODULE_BX_SECURITY_EVENT_RETENTION_DAYS_DESC', 'Retention period in days');
define('MODULE_BX_SECURITY_ADMIN_LOGIN_STATUS_TITLE', 'Admin Login Guard Active');
define('MODULE_BX_SECURITY_ADMIN_LOGIN_STATUS_DESC', 'Logs and throttles series of failed attempts');
define('MODULE_BX_SECURITY_ADMIN_LOGIN_MAX_ATTEMPTS_TITLE', 'Admin Login Failed Attempts');
define('MODULE_BX_SECURITY_ADMIN_LOGIN_MAX_ATTEMPTS_DESC', 'Failed attempts until IP block');
define('MODULE_BX_SECURITY_ADMIN_LOGIN_WINDOW_MINUTES_TITLE', 'Admin Login Evaluation Period');
define('MODULE_BX_SECURITY_ADMIN_LOGIN_WINDOW_MINUTES_DESC', 'Evaluation period in minutes');
define('MODULE_BX_SECURITY_ADMIN_LOGIN_BLOCK_MINUTES_TITLE', 'Admin Login Blocking Duration');
define('MODULE_BX_SECURITY_ADMIN_LOGIN_BLOCK_MINUTES_DESC', 'IP blocking duration in minutes');
define('MODULE_BX_SECURITY_MANUAL_RULES_CACHE_TITLE', 'Manual Rules Cache');
define('MODULE_BX_SECURITY_MANUAL_RULES_CACHE_DESC', 'Automatically generated cache of manual rules');

define('MODULE_BX_SECURITY_MONITOR_TEXT_COULD_NOT_BE_DELETED', 'ERROR! Module <strong>' . constant('MODULE_BX_SECURITY_MONITOR_STATUS_TITLE') . '</strong> could not be deleted.');
define('MODULE_BX_SECURITY_MONITOR_TEXT_SUCCESSFULLY_REMOVED', 'Success! Module <strong>' . constant('MODULE_BX_SECURITY_MONITOR_STATUS_TITLE') . '</strong> was successfully removed.');
define('MODULE_BX_SECURITY_MONITOR_TEXT_REMOVAL_INCOMPLETE', 'ERROR! Module <strong>' . constant('MODULE_BX_SECURITY_MONITOR_STATUS_TITLE') . '</strong> could not be completely removed.');
