<?php
/* -------------------------------------------------------------------------
   Security Monitor for modified eCommerce
   Datei: /includes/modules/bx_guard.php
   Version: 1.2.7

   Unabhängiges Community-Modul. Keine offizielle modified-Erweiterung.
   Lizenz: GPL-2.0-or-later

   Änderungen gegenüber 1.0.0:
   - Länge von Pfad/URI wird vor der Regex-Auswertung begrenzt (ReDoS-Härtung)
   - Bewertungsfenster (INSERT + SUMME + Block-Entscheidung) wird über
     MySQL GET_LOCK() pro IP serialisiert, um Race Conditions bei parallelen
     Requests derselben IP zu vermeiden
   - Housekeeping läuft jetzt intervallbasiert (per APCu-Zeitstempel, sonst
     Fallback auf die alte Zufallslösung) statt rein zufällig
   - Optionales, DB-unabhängiges Rate-Limiting über APCu fängt Requests ab,
     die kein Score-Pattern treffen (z. B. Login-Bruteforce auf legitimen Pfaden)
---------------------------------------------------------------------------*/

if (!function_exists('xtc_db_query') || !function_exists('xtc_db_input')) {
    return;
}

if (!defined('MODULE_BX_SECURITY_MONITOR_STATUS') || MODULE_BX_SECURITY_MONITOR_STATUS !== 'True') {
    return;
}

if (!function_exists('msec_cfg_int')) {
    function msec_cfg_int(string $name, int $default, int $min = 1, int $max = 100000): int {
        $value = defined($name) ? (int)constant($name) : (int)$default;
        return max($min, min($max, $value));
    }
}

if (!function_exists('msec_limit_text')) {
    function msec_limit_text(string $text, int $length): string {
        $text = trim($text);
        if (function_exists('mb_substr')) {
            return mb_substr($text, 0, $length, 'UTF-8');
        }
        return substr($text, 0, $length);
    }
}

if (!function_exists('msec_get_ip')) {
    function msec_get_ip(): string {
        /*
         * Absichtlich nur REMOTE_ADDR. Proxy-Header werden nicht blind
         * vertraut, weil sie ohne verifizierten Proxy faelschbar sind.
         */
        $ip = isset($_SERVER['REMOTE_ADDR']) ? trim((string)$_SERVER['REMOTE_ADDR']) : '';
        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '';
    }
}

if (!function_exists('msec_decode_uri')) {
    function msec_decode_uri(string $value): string {
        for ($i = 0; $i < 2; $i++) {
            $decoded = rawurldecode($value);
            if ($decoded === $value) {
                break;
            }
            $value = $decoded;
        }
        return $value;
    }
}

if (!function_exists('msec_normalize')) {
    function msec_normalize(string $value): string {
        $value = msec_decode_uri($value);
        $value = str_replace('\\', '/', $value);
        $value = preg_replace('#/+#', '/', $value);
        return strtolower($value);
    }
}

if (!function_exists('msec_is_trusted_ip')) {
    function msec_is_trusted_ip(string $ip): bool|int {
        $query = xtc_db_query("
        (SELECT 1 AS trusted 
           FROM msec_whitelist 
          WHERE ip_address = '" . xtc_db_input($ip) . "' LIMIT 1)
          UNION ALL 
           (SELECT 1 AS trusted FROM msec_admin_sessions WHERE ip_address = '" . xtc_db_input($ip) . "' AND expires_at > NOW() LIMIT 1) LIMIT 1 ");
        return xtc_db_num_rows($query) > 0;
    }
}

if (!function_exists('msec_block_response')) {
    function msec_block_response(): never {
        if (!headers_sent()) {
            header('HTTP/1.1 403 Forbidden');
            header('Content-Type: text/plain; charset=utf-8');
            header('X-Robots-Tag: noindex, nofollow', true);
        }
        echo "Zugriff verweigert.";
        exit;
    }
}

if (!function_exists('msec_active_block')) {
    function msec_active_block(string $ip): bool {
        $query = xtc_db_query("SELECT block_id FROM msec_blocks WHERE ip_address = '" . xtc_db_input($ip) . "' AND ( is_permanent = 1 OR blocked_until IS NULL OR blocked_until > NOW() ) LIMIT 1");

        if (xtc_db_num_rows($query) < 1) {
            return false;
        }

        $block = xtc_db_fetch_array($query);
        xtc_db_query("UPDATE msec_blocks SET hits = hits + 1, last_seen = NOW() WHERE block_id = '" . (int)$block['block_id'] . "'");
        return true;
    }
}

if (!function_exists('msec_add_reason')) {
    function msec_add_reason(int &$score, array &$reasons, array &$categories, int $points, string $reason, string $category): void {
        $score += $points;
        $reasons[] = $reason;
        $categories[] = $category;
    }
}

if (!function_exists('msec_match_manual_rules')) {
    function msec_match_manual_rules(string $path, string $uri): array {
        $score = 0;
        $reasons = array();
        $categories = array();

        if (!defined('MODULE_BX_SECURITY_MANUAL_RULES_CACHE') || MODULE_BX_SECURITY_MANUAL_RULES_CACHE === '') {
            return array($score, $reasons, $categories);
        }

        $json = base64_decode((string)MODULE_BX_SECURITY_MANUAL_RULES_CACHE, true);
        $rules = ($json !== false) ? json_decode($json, true) : array();

        if (!is_array($rules)) {
            return array($score, $reasons, $categories);
        }

        $path_norm = msec_normalize($path);
        $uri_norm = msec_normalize($uri);

        foreach ($rules as $rule) {
            if (!is_array($rule) || empty($rule['pattern'])) {
                continue;
            }

            $pattern = msec_normalize($rule['pattern']);
            $type = isset($rule['match_type']) ? (string)$rule['match_type'] : 'contains';
            $points = isset($rule['score']) ? max(1, min(100, (int)$rule['score'])) : 25;
            $matched = false;

            if ($type === 'exact') {
                $matched = ($path_norm === $pattern || $uri_norm === $pattern);
            } elseif ($type === 'prefix') {
                $matched = (strpos($path_norm, $pattern) === 0);
            } else {
                $matched = (strpos($uri_norm, $pattern) !== false);
            }

            if ($matched) {
                msec_add_reason(
                    $score,
                    $reasons,
                    $categories,
                    $points,
                    'Manuelle Regel: ' . $rule['pattern'],
                    'Manuelle Regel'
                );
                break;
            }
        }

        return array($score, $reasons, $categories);
    }
}

if (!function_exists('msec_score_request')) {
    function msec_score_request(string $method, string $path, string $uri): array {
        $score = 0;
        $reasons = array();
        $categories = array();

        /*
         * Härtung gegen ReDoS: Die weiter unten verwendeten Regex-Muster
         * enthalten verschachtelte Quantifizierer. Bei sehr langen, gezielt
         * konstruierten URIs könnte das spürbare CPU-Last erzeugen. Wir
         * begrenzen deshalb die Länge, bevor irgendeine Regex darauf läuft.
         * 2000 Zeichen sind für legitime Requests großzügig bemessen.
         */
        $path = substr((string)$path, 0, 2000);
        $uri = substr((string)$uri, 0, 2000);

        $method = strtoupper((string)$method);
        $path_norm = msec_normalize($path);
        $uri_norm = msec_normalize($uri);
        $base = strtolower(basename($path_norm));

        if (in_array($method, array('TRACE', 'TRACK', 'CONNECT'), true)) {
            msec_add_reason($score, $reasons, $categories, 25, 'Ungewöhnliche HTTP-Methode: ' . $method, 'HTTP-Methode');
        }

        $path_patterns = array(
            array('/.git', 25, 'Git-Verzeichnis', 'Quellcode-/Konfigurationssuche'),
            array('/.env', 25, 'Umgebungsdatei', 'Quellcode-/Konfigurationssuche'),
            array('/.svn', 25, 'SVN-Verzeichnis', 'Quellcode-/Konfigurationssuche'),
            array('/.hg', 25, 'Mercurial-Verzeichnis', 'Quellcode-/Konfigurationssuche'),
            array('/.bzr', 25, 'Bazaar-Verzeichnis', 'Quellcode-/Konfigurationssuche'),
            array('/.vscode', 20, 'VS-Code-Verzeichnis', 'Quellcode-/Konfigurationssuche'),
            array('/.idea', 20, 'IDE-Verzeichnis', 'Quellcode-/Konfigurationssuche'),

            /* modified ist kein WordPress. Diese Pfade sind klare Scannerpfade. */
            array('/wp-', 25, 'WordPress-Pfad', 'WordPress-Scanner'),
            array('/wordpress/', 25, 'WordPress-Verzeichnis', 'WordPress-Scanner'),
            array('/xmlrpc.php', 25, 'WordPress XML-RPC', 'WordPress-Scanner'),
            array('wlwmanifest.xml', 25, 'WordPress Manifest', 'WordPress-Scanner'),

            array('/phpmyadmin', 25, 'phpMyAdmin-Scanner', 'Datenbank-Admin-Scanner'),
            array('/adminer.php', 25, 'Adminer-Datei', 'Datenbank-Admin-Scanner'),
            array('/adminer/', 20, 'Adminer-Verzeichnis', 'Datenbank-Admin-Scanner'),
            array('/pma/', 20, 'PMA-Verzeichnis', 'Datenbank-Admin-Scanner'),
            array('/myadmin/', 20, 'Datenbank-Admin-Verzeichnis', 'Datenbank-Admin-Scanner'),
            array('/dbadmin/', 20, 'Datenbank-Admin-Verzeichnis', 'Datenbank-Admin-Scanner'),

            array('/vendor/phpunit', 25, 'PHPUnit-Exploitpfad', 'Exploit-/Webshell-Scanner'),
            array('/phpunit/', 20, 'PHPUnit-Scanner', 'Exploit-/Webshell-Scanner'),
            array('eval-stdin.php', 25, 'PHPUnit eval-stdin', 'Exploit-/Webshell-Scanner'),
            array('/storage/logs/', 20, 'Anwendungsprotokolle', 'Quellcode-/Konfigurationssuche'),
            array('laravel.log', 25, 'Laravel-Protokoll', 'Quellcode-/Konfigurationssuche'),
            array('/app/etc/local.xml', 25, 'Magento-Konfiguration', 'Quellcode-/Konfigurationssuche'),
            array('/app/etc/env.php', 25, 'Magento-Konfiguration', 'Quellcode-/Konfigurationssuche'),

            array('/server-status', 15, 'Apache Serverstatus', 'Server-/Dienst-Scanner'),
            array('/server-info', 15, 'Apache Serverinfo', 'Server-/Dienst-Scanner'),
            array('/cgi-bin/', 12, 'CGI-Scanner', 'Server-/Dienst-Scanner'),
            array('/autodiscover', 10, 'Autodiscover-Scanner', 'Server-/Dienst-Scanner'),
            array('/owa/', 10, 'OWA-Scanner', 'Server-/Dienst-Scanner'),
            array('/telescope', 18, 'Laravel Telescope', 'Server-/Dienst-Scanner'),
            array('/horizon', 18, 'Laravel Horizon', 'Server-/Dienst-Scanner'),

            /* Kein pauschaler /pub/-Block: modified besitzt selbst einen pub-Ordner. */
            array('/pub/linux/', 25, 'Fremder Linux-Mirrorpfad', 'FTP-/Mirror-Scanner'),
            array('/pub/misc/', 25, 'Fremder Mirrorpfad', 'FTP-/Mirror-Scanner'),
            array('/pub/gnu2/', 25, 'Fremder GNU-Mirrorpfad', 'FTP-/Mirror-Scanner'),

            array('/.ftpconfig', 25, 'FTP-Konfigurationsdatei', 'FTP-/Mirror-Scanner'),
            array('ws_ftp.ini', 25, 'WS_FTP-Konfiguration', 'FTP-/Mirror-Scanner'),
            array('/.netrc', 25, 'Netrc-Zugangsdaten', 'FTP-/Mirror-Scanner'),
            array('sitemanager.xml', 25, 'FileZilla-Sitemanager', 'FTP-/Mirror-Scanner'),
            array('/ftp-sync.json', 20, 'FTP-Sync-Konfiguration', 'FTP-/Mirror-Scanner'),
        );

        foreach ($path_patterns as $item) {
            if (strpos($path_norm, $item[0]) !== false) {
                msec_add_reason($score, $reasons, $categories, $item[1], $item[2], $item[3]);
                break;
            }
        }

        $malware_names = array(
            'shell.php', 'cmd.php', 'wso.php', 'c99.php', 'r57.php', 'b374k.php',
            'mini.php', 'uploader.php', 'filemanager.php', 'chosen.php', 'alfa.php',
            'inputs.php', 'class.api.php', 'priv8.php', 'sym.php',
    
            // NEU: Moderne Webshells & Hacking-Tools
            'p0wny.php', 'powny.php', 'leaf.php', 'cyberking.php', 'godzilla.php', 
            'anubis.php', 'behinder.php', 'vuln.php', 'exfil.php', 'tunnel.php',
            
            // NEU: Getarnte Schadsoftware (Häufige Scanner-Ziele)
            'wp-checks.php', 'db-session.php', 'db-status.php', 'test-env.php', 
            'vulc.php', 'lock.php', 'adm.php', 'system-config.php',
            
            // NEU: Krypto-Miner Steuerdateies / Reste
            'xmrig', 'minerd', 'cpuminer', 'miner.php', 'pool.php'
        );

        foreach ($malware_names as $name) {
            if ($base === $name || strpos($path_norm, '/' . $name) !== false) {
                msec_add_reason($score, $reasons, $categories, 25, 'Verdächtige Datei: ' . $name, 'Exploit-/Webshell-Scanner');
                break;
            }
        }

        if (strpos($path_norm, '../') !== false || strpos($uri_norm, '../') !== false) {
            msec_add_reason($score, $reasons, $categories, 25, 'Verzeichniswechsel ../', 'Path-Traversal/LFI');
        }

        $lfi_patterns = array('/etc/passwd', '/proc/self/environ', 'php://filter', 'php://input', 'expect://', 'file://');
        foreach ($lfi_patterns as $pattern) {
            if (strpos($uri_norm, $pattern) !== false) {
                msec_add_reason($score, $reasons, $categories, 25, 'Datei-/Streamzugriff: ' . $pattern, 'Path-Traversal/LFI');
                break;
            }
        }

        if (preg_match('#\.(sql|bak|backup|old|save|swp)(?:$|\?)#i', $path_norm)) {
            msec_add_reason($score, $reasons, $categories, 20, 'Backup-/Dump-Datei', 'Backup-/Datenbank-Suche');
        }

        if (
            preg_match('#(^|/)(backup|backups|dump|database|mysql|public_html)(\.|/|$)#i', $path_norm)
            || preg_match('#(backup|dump|database|mysql|public_html).+\.(zip|rar|7z|tar|gz|tgz)$#i', $path_norm)
        ) {
            msec_add_reason($score, $reasons, $categories, 12, 'Backup-/Datenbank-Pfad', 'Backup-/Datenbank-Suche');
        }

        if (preg_match('#(?:union(?:\s|/\*.*?\*/)+select|information_schema|sleep\s*\(|benchmark\s*\(|load_file\s*\(|into\s+outfile)#i', $uri_norm)) {
            msec_add_reason($score, $reasons, $categories, 25, 'Klares SQL-Injection-Muster', 'SQL-Injection');
        }

        if (preg_match('#(?:<script|javascript:|onerror\s*=|onload\s*=|document\.cookie)#i', $uri_norm)) {
            msec_add_reason($score, $reasons, $categories, 20, 'Klares XSS-Muster', 'Cross-Site-Scripting');
        }

        if (preg_match('#(?:;|\||&&)\s*(?:wget|curl|bash|sh|powershell|cmd\.exe|whoami)\b#i', $uri_norm)) {
            msec_add_reason($score, $reasons, $categories, 25, 'Klares Befehlsinjektions-Muster', 'Command-Injection');
        }

        if (strpos($uri_norm, 'data:,') !== false || strpos($uri_norm, 'data:text/') !== false) {
            msec_add_reason($score, $reasons, $categories, 12, 'Data-URI in Anfrage', 'Sonstige verdaechtige Anfrage');
        }

        list($manual_score, $manual_reasons, $manual_categories) = msec_match_manual_rules($path, $uri);
        $score += (int)$manual_score;
        $reasons = array_merge($reasons, $manual_reasons);
        $categories = array_merge($categories, $manual_categories);

        return array(
            $score,
            implode(', ', array_unique($reasons)),
            implode(', ', array_unique($categories))
        );
    }
}

if (!function_exists('msec_apcu_available')) {
    function msec_apcu_available(): bool {
        return function_exists('apcu_fetch')
            && function_exists('apcu_store')
            && function_exists('apcu_inc')
            && (!function_exists('apcu_enabled') || apcu_enabled());
    }
}

if (!function_exists('msec_rate_limit_hit')) {
    /*
     * DB-unabhängiges Rate-Limiting über APCu (In-Memory, kein DB-Write
     * pro Request). Fängt Requests ab, die kein Score-Pattern treffen,
     * z. B. Login-Bruteforce auf legitimen Pfaden wie /account_login.php.
     * Degradiert sauber, wenn APCu nicht verfügbar ist (kein Fehler,
     * einfach kein zusätzlicher Schutz durch diesen Baustein).
     *
     * Rückgabe: Anzahl Treffer im aktuellen Fenster, oder 0 wenn APCu fehlt.
     */
    function msec_rate_limit_hit(string $ip, int $limit, int $window_seconds): int {
        if (!msec_apcu_available()) {
            return 0;
        }

        $inc_fn   = 'apcu_inc';
        $store_fn = 'apcu_store';

        if (!is_callable($inc_fn) || !is_callable($store_fn)) {
            return 0;
        }

        $key = 'msec_rl_' . md5($ip);
        $success = false;
        $hits = $inc_fn($key, 1, $success, $window_seconds);

        if ($success === false || $hits === false) {
            $store_fn($key, 1, $window_seconds);
            $hits = 1;
        }

        $hits = (int)$hits;
        if ($hits < 0) {
            $hits = 0;
        }

        if ($limit > 0 && $hits > ($limit + 1)) {
            return $limit + 1;
        }

        return $hits;
    }
}

if (!function_exists('msec_maybe_cleanup')) {
    /*
     * Intervallbasiertes Housekeeping statt reiner Zufallsauswahl. Bei
     * verfügbarem APCu läuft das Cleanup höchstens einmal pro Stunde,
     * unabhängig vom Traffic-Volumen. Ohne APCu greift die alte,
     * probabilistische Lösung als Fallback, damit auch dann irgendwann
     * aufgeräumt wird.
     */
    function msec_maybe_cleanup() {
        if (msec_apcu_available()) {
            $fetch_fn = 'apcu_fetch';
            $store_fn = 'apcu_store';
            if (!is_callable($fetch_fn) || !is_callable($store_fn)) {
                return false;
            }

            $key   = 'msec_last_cleanup';
            $found = false;
            $last  = $fetch_fn($key, $found);
            if ($found && (time() - (int)$last) < 3600) {
                return false;
            }
            $store_fn($key, time());
            return true;
        }

        return mt_rand(1, 100) === 1;
    }
}

$ip = msec_get_ip();
if ($ip === '') {
    return;
}

if (msec_is_trusted_ip($ip)) {
    return;
}

if (msec_active_block($ip)) {
    msec_block_response();
}

/*
 * Generisches Rate-Limiting, unabhängig vom Pattern-Score. Ohne diesen
 * Baustein würde z. B. Login-Bruteforce auf einem legitimen Pfad wie
 * /account_login.php nie erfasst, weil dort kein verdächtiges Muster
 * matcht. Fällt sauber weg, wenn APCu nicht installiert ist.
 */
$rate_limit  = msec_cfg_int('BX_SECURITY_RATE_LIMIT_REQUESTS', 120, 5, 100000);
$rate_window = msec_cfg_int('BX_SECURITY_RATE_LIMIT_WINDOW_SECONDS', 60, 5, 3600);
$rate_hits   = msec_rate_limit_hit($ip, $rate_limit, $rate_window);

if ($rate_hits > $rate_limit) {
    $block_hours = msec_cfg_int('MODULE_BX_SECURITY_BLOCK_HOURS', 24, 1, 8760);
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
                                                   'Rate-Limit ueberschritten: " . (int)$rate_hits . " Requests in " . (int)$rate_window . "s',
                                                   0,
                                                   '" . (int)$rate_hits . "',
                                                   NOW(),
                                                   NOW(),
                                                   DATE_ADD(NOW(), INTERVAL " . (int)$block_hours . " HOUR),
                                                   0,
                                                   '" . xtc_db_input(isset($_SERVER['HTTP_USER_AGENT']) ? msec_limit_text($_SERVER['HTTP_USER_AGENT'], 255) : '') . "')
                                                    ON DUPLICATE KEY UPDATE
                                                        reason = VALUES(reason),
                                                        hits = VALUES(hits),
                                                        last_seen = NOW(),
                                                        blocked_until = DATE_ADD(NOW(), INTERVAL " . (int)$block_hours . " HOUR),
                                                        user_agent = VALUES(user_agent)
                                                ");
    msec_block_response();
}

$request_uri  = isset($_SERVER['REQUEST_URI']) ? (string)$_SERVER['REQUEST_URI'] : '';
$request_path = parse_url($request_uri, PHP_URL_PATH);

if ($request_path === null || $request_path === false) {
    $request_path = $request_uri;
}
$request_method = isset($_SERVER['REQUEST_METHOD']) ? (string)$_SERVER['REQUEST_METHOD'] : 'GET';
$user_agent     = isset($_SERVER['HTTP_USER_AGENT']) ? msec_limit_text($_SERVER['HTTP_USER_AGENT'], 255) : '';
$referer        = isset($_SERVER['HTTP_REFERER']) ? msec_limit_text($_SERVER['HTTP_REFERER'], 600) : '';

list($score, $reason, $category) = msec_score_request($request_method, $request_path, $request_uri);
if ($score <= 0) {
    return;
}

/*
 * Ab hier folgen INSERT (Event) -> SELECT SUM() (Fenster) -> ggf. INSERT
 * (Block). Ohne Sperre können mehrere parallele Requests derselben IP
 * (z. B. ein schneller Scanner) diese Sequenz gleichzeitig durchlaufen und
 * dabei jeweils unter dem Schwellenwert bleiben, obwohl die Summe längst
 * ausreicht. MySQL GET_LOCK() serialisiert das pro IP, ohne dass ein neues
 * Tabellenschema nötig ist. Die Sperre wird am Ende des Requests durch das
 * Schließen der DB-Verbindung ohnehin freigegeben; RELEASE_LOCK() räumt
 * sie im Normalfall trotzdem explizit auf.
 */
$lock_name     = 'msec_' . md5($ip);
$lock_acquired = false;

$lock_query = xtc_db_query("SELECT GET_LOCK('" . xtc_db_input($lock_name) . "', 2) AS locked");

if ($lock_query) {
    $lock_row      = xtc_db_fetch_array($lock_query);
    $lock_acquired = isset($lock_row['locked']) && (int)$lock_row['locked'] === 1;
}

xtc_db_query("INSERT INTO msec_events (ip_address, 
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
                                              '" . xtc_db_input(msec_limit_text($request_uri, 600)) . "',
                                              '" . xtc_db_input(msec_limit_text($request_path, 600)) . "',
                                              '" . xtc_db_input(msec_limit_text($request_method, 10)) . "',
                                              '" . xtc_db_input($user_agent) . "',
                                              '" . xtc_db_input($referer) . "',
                                              '" . xtc_db_input(msec_limit_text($reason, 255)) . "',
                                              '" . xtc_db_input(msec_limit_text($category, 120)) . "',
                                              '" . (int)$score . "',
                                              0,
                                              NOW()
                                              )");
$event_id = xtc_db_insert_id();

$window_minutes = msec_cfg_int('MODULE_BX_SECURITY_SCORE_WINDOW_MINUTES', 10, 1, 1440);
$threshold      = msec_cfg_int('MODULE_BX_SECURITY_BLOCK_THRESHOLD', 25, 1, 500);
$block_hours    = msec_cfg_int('MODULE_BX_SECURITY_BLOCK_HOURS', 24, 1, 8760);

$summary_query = xtc_db_query("SELECT SUM(score) AS total_score, COUNT(*) AS hits, COUNT(DISTINCT request_path) AS different_paths, MIN(date_added) AS first_seen FROM msec_events WHERE ip_address = '" . xtc_db_input($ip) . "' AND date_added >= DATE_SUB(NOW(), INTERVAL " . (int)$window_minutes . " MINUTE)");
$summary       = xtc_db_fetch_array($summary_query);

$total_score     = isset($summary['total_score']) ? (int)$summary['total_score'] : 0;
$hits            = isset($summary['hits']) ? (int)$summary['hits'] : 0;
$different_paths = isset($summary['different_paths']) ? (int)$summary['different_paths'] : 0;
$first_seen      = !empty($summary['first_seen']) ? $summary['first_seen'] : date('Y-m-d H:i:s');

$should_block = false;
$block_reason = '';

if ($score >= $threshold) {
    $should_block = true;
    $block_reason = 'Sofortblock: ' . $reason;
} elseif ($total_score >= $threshold) {
    $should_block = true;
    $block_reason = 'Scanner erkannt: ' . $total_score . ' Punkte in ' . $window_minutes . ' Minuten';
} elseif ($different_paths >= 8 && $hits >= 8) {
    $should_block = true;
    $block_reason = 'Scanner erkannt: ' . $different_paths . ' verschiedene verdächtige Pfade';
}

if ($should_block) {
    xtc_db_query("INSERT INTO msec_blocks (ip_address, reason, score, hits, first_seen, last_seen, blocked_until, is_permanent, user_agent) VALUES ('" . xtc_db_input($ip) . "',\n            '" . xtc_db_input(msec_limit_text($block_reason, 255)) . "',\n            '" . (int)$total_score . "',\n            '" . (int)$hits . "',\n            '" . xtc_db_input($first_seen) . "',\n            NOW(),\n            DATE_ADD(NOW(), INTERVAL " . (int)$block_hours . " HOUR),\n            0,\n            '" . xtc_db_input($user_agent) . "'\n        )\n        ON DUPLICATE KEY UPDATE\n            reason = VALUES(reason),\n            score = VALUES(score),\n            hits = VALUES(hits),\n            last_seen = NOW(),\n            blocked_until = DATE_ADD(NOW(), INTERVAL " . (int)$block_hours . " HOUR), user_agent = VALUES(user_agent)");

    xtc_db_query("UPDATE msec_events SET is_blocked = 1 WHERE event_id = '" . (int)$event_id . "'");

    if ($lock_acquired) {
        xtc_db_query("SELECT RELEASE_LOCK('" . xtc_db_input($lock_name) . "')");
    }

    msec_block_response();
}

if ($lock_acquired) {
    xtc_db_query("SELECT RELEASE_LOCK('" . xtc_db_input($lock_name) . "')");
}

if (msec_maybe_cleanup()) {
    $retention_days = msec_cfg_int('MODULE_BX_SECURITY_EVENT_RETENTION_DAYS', 14, 1, 3650);
    xtc_db_query("DELETE FROM msec_events WHERE date_added < DATE_SUB(NOW(), INTERVAL " . (int)$retention_days . " DAY)");
    xtc_db_query("DELETE FROM msec_blocks WHERE is_permanent = 0 AND blocked_until IS NOT NULL AND blocked_until < DATE_SUB(NOW(), INTERVAL 2 DAY)");
    xtc_db_query("DELETE FROM msec_admin_sessions WHERE expires_at < NOW()");
}
