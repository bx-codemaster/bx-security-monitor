<?php
/**
 * English language file for the system module bx_security_monitor.
 * /lang/english/extra/admin/bx_security_monitor.php

 * This file defines the English module texts for configuration,
 * installation notes, and error messages in the modified admin area.
 *
 * @file        bx_security_monitor.php
 * @package     bx-security-monitor
 * @author      bx-codemaster (benax)
 * @website     www.bx-coding.de
 * @license     GNU General Public License (GPL)
 * @since       2026-07-10
 */

define('BX_SECURITY_MONITOR_TITLE', 'BX Security Monitor - <span style="font-weight: normal;">Security monitoring</span>');
define('BX_SECURITY_MONITOR_DESCRIPTION', 'This module monitors security-related events in the shop and provides protection mechanisms against attacks.');
define('BX_SECURITY_MONITOR_TITLE_TAG', 'BX Security Monitor - Security monitoring');
define('BX_SECURITY_MONITOR_TITLE_NOTE', 'This page only evaluates security events. It does not monitor or modify shop files and does not block administrator accounts. A logged attack is not proof of a successful breach.');
define('BX_SECURITY_MONITOR_TXT_CURRENT_ACTIVITY', 'Current activity');

define('BX_SECURITY_MONITOR_SETTINGS_SAVED', 'Settings have been saved.');
define('BX_SECURITY_MONITOR_RULE_SAVED', 'Rule has been saved.');
define('BX_SECURITY_MONITOR_INVALID_DELETE_RULE_CALL', 'Invalid call for deleting a manual rule.');
define('BX_SECURITY_MONITOR_INVALID_ADD_RULE_CALL', 'Invalid call for adding a manual rule.');
define('BX_SECURITY_MONITOR_RULE_ADDED', 'Rule has been added.');

define('BX_SECURITY_MONITOR_BURST_FROM_IP', 'Burst of requests from an IP');
define('BX_SECURITY_MONITOR_BURST_FROM_IP_TEXT', '%s: %d suspicious hits in 15 minutes');
define('BX_SECURITY_MONITOR_DISTRIBUTED_SCAN', 'Distributed scan on the same path');
define('BX_SECURITY_MONITOR_DISTRIBUTED_SCAN_TEXT', '%d IPs accessed %s within an hour');

define('BX_SECURITY_MONITOR_HIGH_SCANNER_ACTIVITY', 'High scanner activity');
define('BX_SECURITY_MONITOR_HIGH_SCANNER_ACTIVITY_NOTE', 'Multiple or heavily clustered suspicious requests have been detected.');
define('BX_SECURITY_MONITOR_MEDIUM_SCANNER_ACTIVITY', 'Increased activity');
define('BX_SECURITY_MONITOR_MEDIUM_SCANNER_ACTIVITY_NOTE', 'Recently, unusual requests or clusters have been detected.');
define('BX_SECURITY_MONITOR_LOW_SCANNER_ACTIVITY', 'Calm situation');
define('BX_SECURITY_MONITOR_LOW_SCANNER_ACTIVITY_NOTE', 'Currently, no unusual clustering is visible.');

define('BX_SECURITY_MONITOR_INVALID_SAVE_CALL', 'Invalid call for saving settings.');
define('BX_SECURITY_MONITOR_RULE_DELETED', 'Rule has been deleted.');
define('BX_SECURITY_MONITOR_INVALID_TOGGLE_RULE_CALL', 'Invalid call for toggling the rule.');
define('BX_SECURITY_MONITOR_STATUS_UPDATED', 'Status has been updated.');
define('BX_SECURITY_MONITOR_INVALID_UNBLOCK_CALL', 'Invalid call for unblocking the entry.');
define('BX_SECURITY_MONITOR_ENTRY_UNBLOCKED', 'Entry has been unblocked.');
define('BX_SECURITY_MONITOR_INVALID_ADD_WHITELIST_CALL', 'Invalid call for adding to the whitelist.');
define('BX_SECURITY_MONITOR_LIST_UPDATED', 'List has been updated.');
define('BX_SECURITY_MONITOR_INVALID_BLOCK_TO_WHITELIST_CALL', 'Invalid call for taking over the entry to the whitelist.');
define('BX_SECURITY_MONITOR_ENTRY_TAKEN_OVER', 'Entry has been taken over.');
define('BX_SECURITY_MONITOR_INVALID_DELETE_WHITELIST_CALL', 'Invalid call for deleting from the whitelist.');
define('BX_SECURITY_MONITOR_WHITELIST_ENTRY_DELETED', 'Whitelist entry has been deleted.');
define('BX_SECURITY_MONITOR_INVALID_CLEAR_EVENTS_CALL', 'Invalid call for clearing events.');
define('BX_SECURITY_MONITOR_EVENTS_CLEARED', 'Events have been cleared.');
define('BX_SECURITY_MONITOR_INVALID_CLEAR_EXPIRED_CALL', 'Invalid call for clearing expired blocks.');
define('BX_SECURITY_MONITOR_EXPIRED_BLOCKS_CLEARED', 'Expired blocks have been cleared.');

define('BX_SECURITY_MONITOR_HITS_10_MIN', 'Hits 10 min.');
define('BX_SECURITY_MONITOR_HITS_1_HOUR', 'Hits 1 hour');
define('BX_SECURITY_MONITOR_HITS_24_HOURS', 'Hits 24 hours');
define('BX_SECURITY_MONITOR_IPS_24_HOURS', 'IPs 24 hours');
define('BX_SECURITY_MONITOR_BLOCKED_EVENTS', 'Blocked events');
define('BX_SECURITY_MONITOR_ACTIVE_IP_BLOCKS', 'Active IP blocks');
define('BX_SECURITY_MONITOR_UNUSUAL_ACTIVITY', 'Unusual activity');
define('BX_SECURITY_MONITOR_NO_UNUSUAL_ACTIVITY', 'No unusual activity in the evaluated time windows.');
define('BX_SECURITY_MONITOR_DETECTED_ATTACK_TYPES_24_HOURS', 'Detected attack types – 24 hours');
define('BX_SECURITY_MONITOR_NO_EVENTS', 'No events.');
define('BX_SECURITY_MONITOR_ACTIVITY_OVERVIEW_24_HOURS', 'Activity overview – 24 hours');
define('BX_SECURITY_MONITOR_TOP_ATTACKING_IPS_24_HOURS', 'Top attacking IPs – 24 hours');
define('BX_SECURITY_MONITOR_MOST_ATTACKED_PATHS_24_HOURS', 'Most attacked paths – 24 hours');
define('BX_SECURITY_MONITOR_LAST_CRITICAL_OR_BLOCKED_EVENTS', 'Last critical or blocked events');

define('BX_SECURITY_MONITOR_TH_IP', 'IP');
define('BX_SECURITY_MONITOR_TH_HITS', 'Hits');
define('BX_SECURITY_MONITOR_TH_SCORE', 'Score');
define('BX_SECURITY_MONITOR_TH_BLOCKED', 'Blocked');
define('BX_SECURITY_MONITOR_TH_LAST_SEEN', 'Last seen');
define('BX_SECURITY_MONITOR_TH_PATH', 'Path');
define('BX_SECURITY_MONITOR_TH_REASON', 'Reason');
define('BX_SECURITY_MONITOR_TH_IPS', 'IPs');
define('BX_SECURITY_MONITOR_TH_TIME', 'Time');
define('BX_SECURITY_MONITOR_TH_METHOD', 'Method');
define('BX_SECURITY_MONITOR_TH_CATEGORY', 'Category');
define('BX_SECURITY_MONITOR_TH_STATUS', 'Status');
define('BX_SECURITY_MONITOR_NO_CRITICAL_EVENTS', 'No critical events.');

define('BX_SECURITY_MONITOR_SETTINGS', 'Settings');
define('BX_SECURITY_MONITOR_ACTIVE', 'Active');
define('BX_SECURITY_MONITOR_INACTIVE', 'Inactive');

define('BX_SECURITY_MONITOR_BLOCK_THRESHOLD', 'Block threshold (points)');
define('BX_SECURITY_MONITOR_SCORE_WINDOW_MINUTES', 'Score window (minutes)');
define('BX_SECURITY_MONITOR_BLOCK_HOURS', 'Automatic block duration (hours)');
define('BX_SECURITY_MONITOR_EVENT_RETENTION_DAYS', 'Retain events (days)');
define('BX_SECURITY_MONITOR_ADMIN_LOGIN_STATUS', 'Admin login guard');
define('BX_SECURITY_MONITOR_ADMIN_LOGIN_MAX_ATTEMPTS', 'Admin failed attempts before block');
define('BX_SECURITY_MONITOR_ADMIN_LOGIN_WINDOW_MINUTES', 'Admin evaluation window (minutes)');
define('BX_SECURITY_MONITOR_ADMIN_LOGIN_BLOCK_MINUTES', 'Admin IP block (minutes)');
define('BX_SECURITY_MONITOR_SAVE_SETTINGS', 'Save settings');

define('BX_SECURITY_MONITOR_MANUAL_RULES', 'Manual rules');
define('BX_SECURITY_MONITOR_MANUAL_RULES_WARNING', 'Manual rules are powerful. For normal shop pages, use <strong>prefix</strong> or <strong>exact</strong> whenever possible. An overly broad substring rule can match legitimate URLs.');
define('BX_SECURITY_MONITOR_PATTERN', 'Pattern');
define('BX_SECURITY_MONITOR_COMPARISON', 'Comparison');
define('BX_SECURITY_MONITOR_MATCH_PREFIX', 'Path starts with');
define('BX_SECURITY_MONITOR_MATCH_EXACT', 'Exact path');
define('BX_SECURITY_MONITOR_MATCH_CONTAINS', 'Substring in URL');
define('BX_SECURITY_MONITOR_ADD_RULE', 'Add rule');
define('BX_SECURITY_MONITOR_TH_ACTION', 'Action');
define('BX_SECURITY_MONITOR_NO_MANUAL_RULES', 'No manual rules.');
define('BX_SECURITY_MONITOR_CONFIRM_TOGGLE_RULE_STATUS', 'Toggle rule status?');
define('BX_SECURITY_MONITOR_TOGGLE', 'Toggle');
define('BX_SECURITY_MONITOR_CONFIRM_DELETE_RULE', 'Delete rule?');
define('BX_SECURITY_MONITOR_DELETE', 'Delete');

define('BX_SECURITY_MONITOR_ACTIVE_AUTO_BLOCKS', 'Active automatic blocks');
define('BX_SECURITY_MONITOR_DELETE_EXPIRED_ENTRIES', 'Delete expired entries');
define('BX_SECURITY_MONITOR_TH_BLOCKED_UNTIL', 'Blocked until');
define('BX_SECURITY_MONITOR_NO_ACTIVE_BLOCKS', 'No active blocks.');
define('BX_SECURITY_MONITOR_PERMANENT', 'Permanent');
define('BX_SECURITY_MONITOR_UNBLOCK', 'Unblock');
define('BX_SECURITY_MONITOR_CONFIRM_BLOCK_TO_WHITELIST', 'Unblock IP and add to whitelist permanently?');
define('BX_SECURITY_MONITOR_WHITELIST', 'Whitelist');

define('BX_SECURITY_MONITOR_PERMANENT_WHITELIST', 'Permanent whitelist');
define('BX_SECURITY_MONITOR_IP_ADDRESS', 'IP address');
define('BX_SECURITY_MONITOR_NOTE', 'Note');
define('BX_SECURITY_MONITOR_ADD', 'Add');
define('BX_SECURITY_MONITOR_ALLOW_CURRENT_ADMIN_IP', 'Allow current admin IP permanently');
define('BX_SECURITY_MONITOR_TH_CREATED', 'Created');
define('BX_SECURITY_MONITOR_NO_ENTRIES', 'No entries.');
define('BX_SECURITY_MONITOR_CONFIRM_DELETE_WHITELIST_ENTRY', 'Delete whitelist entry?');

define('BX_SECURITY_MONITOR_TEMP_ADMIN_APPROVALS', 'Temporary admin approvals');
define('BX_SECURITY_MONITOR_TEMP_ADMIN_APPROVALS_INFO', 'Successfully logged-in admin sessions are automatically approved for 30 minutes and extended with each admin request.');
define('BX_SECURITY_MONITOR_TH_ADMIN_ID', 'Admin ID');
define('BX_SECURITY_MONITOR_TH_EXPIRES_AT', 'Expires at');
define('BX_SECURITY_MONITOR_NO_ACTIVE_ADMIN_APPROVALS', 'No active admin approvals.');

define('BX_SECURITY_MONITOR_LATEST_SECURITY_EVENTS', 'Latest security events');
define('BX_SECURITY_MONITOR_CONFIRM_CLEAR_EVENTS', 'Clear all security events? Existing blocks will remain.');
define('BX_SECURITY_MONITOR_CLEAR_EVENTS_LOG', 'Clear events log');
define('BX_SECURITY_MONITOR_TH_URL', 'URL');
define('BX_SECURITY_MONITOR_TH_USER_AGENT', 'User-Agent');
define('BX_SECURITY_MONITOR_NO_EVENTS_YET', 'No events yet.');
define('BX_SECURITY_MONITOR_YES', 'Yes');
define('BX_SECURITY_MONITOR_NO', 'No');
