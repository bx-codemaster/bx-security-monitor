<?php
/* -------------------------------------------------------------------------
   Passiver Admin-Login-Wächter
   Datei: /includes/modules/bx_admin_login_guard.php
   Version: 1.1.0

   Keine Kontosperre, keine 2FA, keine festen Admin-IP-Adressen.
---------------------------------------------------------------------------*/

if (!function_exists('xtc_db_query') || !function_exists('xtc_db_input')) {
    return;
}

if (
    !defined('MODULE_BX_SECURITY_MONITOR_STATUS')
    || MODULE_BX_SECURITY_MONITOR_STATUS !== 'True'
    || !defined('MODULE_BX_SECURITY_ADMIN_LOGIN_STATUS')
    || MODULE_BX_SECURITY_ADMIN_LOGIN_STATUS !== 'True'
) {
    return;
}

if (!function_exists('msec_login_get_ip')) {
    function msec_login_get_ip(): string {
        $ip = isset($_SERVER['REMOTE_ADDR']) ? trim((string)$_SERVER['REMOTE_ADDR']) : '';
        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '';
    }
}

if (!function_exists('msec_login_limit')) {
    function msec_login_limit(string $text, int $length): string {
        $text = trim($text);
        if (function_exists('mb_substr')) {
            return mb_substr($text, 0, $length, 'UTF-8');
        }
        return substr($text, 0, $length);
    }
}

if (!function_exists('msec_login_get_session_id')) {
    function msec_login_get_session_id(): string {
        if (!function_exists('session_id')) {
            return '';
        }

        $sid = session_id();
        if (!is_string($sid) || $sid === '') {
            return '';
        }

        return msec_login_limit($sid, 128);
    }
}

if (!function_exists('msec_login_trusted')) {
    function msec_login_trusted(string $ip): bool {
        $sid   = msec_login_get_session_id();
        /**
         * Ist die IP-Adresse bekannt (Whitelist) ODER hat der Nutzer eine gültige, noch nicht abgelaufene Admin-Session von dieser IP aus?
         * Wenn ja, liefert die Datenbank eine 1 zurück und der Nutzer darf passieren.
         */
        $query = xtc_db_query("(SELECT 1 AS trusted FROM msec_whitelist 
                                        WHERE ip_address = '" . xtc_db_input($ip) . "' LIMIT 1)
                                          UNION ALL (SELECT 1 AS trusted FROM msec_admin_sessions
                                          WHERE ip_address = '" . xtc_db_input($ip) . "' 
                                        AND admin_session_id = '" . xtc_db_input($sid) . "'
                                        AND expires_at > NOW() LIMIT 1) LIMIT 1");
        return xtc_db_num_rows($query) > 0;
    }
}

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

if (!function_exists('msec_register_failed_admin_login')) {
    function msec_register_failed_admin_login(): void {
        $ip = msec_login_get_ip();
        if ($ip === '') {
            return;
        }

        $request_uri  = isset($_SERVER['REQUEST_URI']) ? (string)$_SERVER['REQUEST_URI'] : '/login.php';
        $request_path = parse_url($request_uri, PHP_URL_PATH);

        if ($request_path === null || $request_path === false || $request_path === '') {
            $request_path = '/login.php';
        }

        $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? msec_login_limit($_SERVER['HTTP_USER_AGENT'], 255) : '';
        $referer    = isset($_SERVER['HTTP_REFERER'])    ? msec_login_limit($_SERVER['HTTP_REFERER'], 600) : '';

        xtc_db_query("INSERT INTO msec_events (
                                   ip_address, 
                                   request_uri, 
                                   request_path, 
                                   request_method, 
                                   user_agent, 
                                   referer,
                                   reason, 
                                   category, 
                                   score, 
                                   is_blocked, 
                                   date_added) 
                          VALUES ('" . xtc_db_input($ip) . "',
                                  '" . xtc_db_input(msec_login_limit($request_uri, 600)) . "',
                                  '" . xtc_db_input(msec_login_limit($request_path, 600)) . "',
                                  'POST',
                                  '" . xtc_db_input($user_agent) . "',
                                  '" . xtc_db_input($referer) . "',
                                  'Fehlgeschlagener Admin-Login',
                                  'Admin-Login',
                                  1,
                                  0,
                                  NOW())");
        $event_id = xtc_db_insert_id();

        $window        = defined('MODULE_BX_SECURITY_ADMIN_LOGIN_WINDOW_MINUTES') ? max(1, min(1440, (int)MODULE_BX_SECURITY_ADMIN_LOGIN_WINDOW_MINUTES)) : 15;
        $max_attempts  = defined('MODULE_BX_SECURITY_ADMIN_LOGIN_MAX_ATTEMPTS')   ? max(3, min(1000, (int)MODULE_BX_SECURITY_ADMIN_LOGIN_MAX_ATTEMPTS)) : 10;
        $block_minutes = defined('MODULE_BX_SECURITY_ADMIN_LOGIN_BLOCK_MINUTES')  ? max(1, min(10080, (int)MODULE_BX_SECURITY_ADMIN_LOGIN_BLOCK_MINUTES)) : 60;

        $query = xtc_db_query("SELECT COUNT(*) AS attempts, MIN(date_added) AS first_seen 
                                       FROM msec_events 
                                      WHERE ip_address = '" . xtc_db_input($ip) . "'
                                        AND category = 'Admin-Login'
                                        AND date_added >= DATE_SUB(NOW(), INTERVAL " . (int)$window . " MINUTE)");
        
        $data       = xtc_db_fetch_array($query);
        $attempts   = isset($data['attempts']) ? (int)$data['attempts'] : 1;
        $first_seen = !empty($data['first_seen']) ? $data['first_seen'] : date('Y-m-d H:i:s');

        /* Freigegebene Admin-IP: protokollieren, aber nie verlangsamen/sperren. */
        if (msec_login_trusted($ip)) {
            return;
        }

        if ($attempts >= $max_attempts) {
            $reason = 'Admin-Login-Schutz: ' . $attempts . ' Fehlversuche in ' . $window . ' Minuten';
            xtc_db_query("INSERT INTO msec_blocks ( ip_address, 
                                                           reason, 
                                                           score, 
                                                           hits, 
                                                           first_seen, 
                                                           last_seen, 
                                                           blocked_until,
                                                           is_permanent, 
                                                           user_agent) 
                                                   VALUES ('" . xtc_db_input($ip) . "',
                                                           '" . xtc_db_input($reason) . "',
                                                           '" . (int)$attempts . "',
                                                           '" . (int)$attempts . "',
                                                           '" . xtc_db_input($first_seen) . "',
                                                           NOW(),
                                                           DATE_ADD(NOW(), INTERVAL " . (int)$block_minutes . " MINUTE),
                                                           0,
                                                           '" . xtc_db_input($user_agent) . "')
                                                           ON DUPLICATE KEY UPDATE reason = VALUES(reason), 
                                                                                    score = VALUES(score), 
                                                                                    hits = VALUES(hits),
                                                                                    last_seen = NOW(),
                                                                                    blocked_until = DATE_ADD(NOW(), 
                                                                                    INTERVAL " . (int)$block_minutes . " MINUTE),
                                                                                    user_agent = VALUES(user_agent)");
            xtc_db_query("UPDATE msec_events SET is_blocked = 1 WHERE event_id = '" . (int)$event_id . "'");

            if (!headers_sent()) {
                if (function_exists('header_remove')) {
                    header_remove('Location');
                }
                header('HTTP/1.1 403 Forbidden');
                header('Content-Type: text/plain; charset=utf-8');
            }
            echo "Zu viele fehlgeschlagene Anmeldeversuche. Bitte später erneut versuchen.";
            return;
        }

        $delay = 0;
        if ($attempts >= 7) {
            $delay = 4;
        } elseif ($attempts >= 5) {
            $delay = 2;
        } elseif ($attempts >= 3) {
            $delay = 1;
        }
        if ($delay > 0) {
            sleep($delay);
        }
    }
}

if (!function_exists('msec_admin_login_shutdown')) {
    function msec_admin_login_shutdown(): void {
        $script = isset($_SERVER['SCRIPT_NAME']) ? strtolower(basename($_SERVER['SCRIPT_NAME'])) : '';

        // login_admin.php setzt keine Shop-Session für erfolgreiche Reparatur-Logins.
        // Der Aufrufer markiert in diesem Fall explizit fehlgeschlagene Versuche.
        if ($script === 'login_admin.php') {
            $failed = !empty($GLOBALS['msec_login_admin_failed']);
            if ($failed) {
                msec_register_failed_admin_login();
            }
            return;
        }

        $is_admin = (
            isset($_SESSION['customer_id'])
            && msec_is_admin_customer((int)$_SESSION['customer_id'])
        );

        if (!$is_admin) {
            msec_register_failed_admin_login();
        }
    }
}

$script = isset($_SERVER['SCRIPT_NAME']) ? strtolower(basename($_SERVER['SCRIPT_NAME'])) : '';
$is_admin_login_post = (
    (
        $script === 'login.php'
        && isset($_SERVER['REQUEST_METHOD'])
        && strtoupper((string)$_SERVER['REQUEST_METHOD']) === 'POST'
        && isset($_POST['login'])
        && (string)$_POST['login'] === 'admin'
    )
    || (
        $script === 'login_admin.php'
        && isset($_SERVER['REQUEST_METHOD'])
        && strtoupper((string)$_SERVER['REQUEST_METHOD']) === 'POST'
        && (isset($_POST['repair']) || isset($_POST['show_error']))
    )
);

if ($is_admin_login_post) {
    register_shutdown_function('msec_admin_login_shutdown');
}
