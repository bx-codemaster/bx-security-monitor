<?php
if (!function_exists('msec_is_admin_customer')) {
    function msec_is_admin_customer(int $customer_id): bool {
        if ($customer_id <= 0) {
            return false;
        }

        $table_customers = defined('TABLE_CUSTOMERS') ? TABLE_CUSTOMERS : 'customers';
        $query = xtc_db_query("SELECT customers_status
                     FROM " . $table_customers . "
                                WHERE customers_id = '" . (int)$customer_id . "'
                                LIMIT 1");
        if (!$query || xtc_db_num_rows($query) < 1) {
            return false;
        }

        $data = xtc_db_fetch_array($query);
        return isset($data['customers_status']) && (string)$data['customers_status'] === '0';
    }
}

/* Aktive Admin-Sitzung für Monitoring-Zwecke erfassen/aktualisieren. */
if (
    defined('MODULE_BX_SECURITY_MONITOR_STATUS')
    && MODULE_BX_SECURITY_MONITOR_STATUS === 'True'
    && isset($_SESSION['customer_id'])
    && function_exists('xtc_db_query')
    && msec_is_admin_customer((int)$_SESSION['customer_id'])
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
                                                                                                          expires_at = DATE_ADD(NOW(), 
                                                                                                          INTERVAL 30 MINUTE)");
    }

    if (mt_rand(1, 30) === 1) { // ~3% Chance pro Request, altes Cleanup durchführen
        xtc_db_query("DELETE FROM msec_admin_sessions WHERE expires_at < NOW()");
    }
}
