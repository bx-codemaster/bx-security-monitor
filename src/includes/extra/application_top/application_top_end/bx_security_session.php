<?php
/* Aktive Admin-Sitzung für Monitoring-Zwecke erfassen/aktualisieren. */
if (
    defined('MODULE_BX_SECURITY_MONITOR_STATUS')
    && MODULE_BX_SECURITY_MONITOR_STATUS === 'True'
    && isset($_SESSION['customer_id'])
    && isset($_SESSION['customers_status']['customers_status_id'])
    && (string)$_SESSION['customers_status']['customers_status_id'] === '0'
    && function_exists('xtc_db_query')
) {
    $ip  = isset($_SERVER['REMOTE_ADDR']) ? trim((string)$_SERVER['REMOTE_ADDR']) : '';
    $sid = session_id();

    if (filter_var($ip, FILTER_VALIDATE_IP) && $sid !== '') {
        xtc_db_query("INSERT INTO msec_admin_sessions (ip_address, 
                                                             admin_customers_id, 
                                                             admin_session_id, 
                                                             date_added, 
                                                             last_seen, 
                                                             expires_at) 
                                                     VALUES ('" . xtc_db_input($ip) . "',
                                                             '" . (int)$_SESSION['customer_id'] . "',
                                                             '" . xtc_db_input(substr($sid, 0, 128)) . "',
                                                             NOW(), 
                                                             NOW(), 
                                                             DATE_ADD(NOW(), 
                                                             INTERVAL 30 MINUTE))
                                                     ON DUPLICATE KEY UPDATE admin_customers_id = VALUES( admin_customers_id),
                                                                                                          last_seen = NOW(),
                                                                                                          expires_at = DATE_ADD(NOW(), INTERVAL 30 MINUTE)");
    }

    if (mt_rand(1, 30) === 1) { // ~3% Chance pro Request, altes Cleanup durchführen
        xtc_db_query("DELETE FROM msec_admin_sessions WHERE expires_at < NOW()");
    }
}
