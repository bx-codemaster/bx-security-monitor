<?php
/** --------------------------------------------------------------
 * $Id: admin/bx_security_monitor.php 2026-07-10 12:00:00Z benax $
 * modified eCommerce Shopsoftware
 * http://www.modified-shop.org
 * 
 * Copyright (c) 2009 - 2013 [www.modified-shop.org]
 * --------------------------------------------------------------
 * based on:
 * (c) 2000-2001 The Exchange Project  (earlier name of osCommerce)
 * (c) 2002-2003 osCommercecoding standards www.oscommerce.com
 * (c) 2003	nextcommerce www.nextcommerce.org
 * (c) 2003 XT-Commerce
 * 
 * Released under the GNU General Public License
 * --------------------------------------------------------------
 * Unter Mitwirkung von CADDY entwickelt
 * CADDY: Computer-Aided Development & Deployment Yield (AI)
 */

require ('includes/application_top.php');

xtc_db_query("DELETE FROM msec_blocks WHERE is_permanent = 0 AND blocked_until IS NOT NULL AND blocked_until <= NOW()");
xtc_db_query("DELETE FROM msec_admin_sessions WHERE expires_at <= NOW()");

$q = xtc_db_query("SELECT COUNT(*) AS total FROM msec_events WHERE date_added >= DATE_SUB(NOW(), INTERVAL 10 MINUTE)"); 
$events10 = xtc_db_fetch_array($q);

$q = xtc_db_query("SELECT COUNT(*) AS total FROM msec_events WHERE date_added >= DATE_SUB(NOW(), INTERVAL 1 HOUR)"); 
$events1h = xtc_db_fetch_array($q);

$q = xtc_db_query("SELECT COUNT(*) AS total FROM msec_events WHERE date_added >= DATE_SUB(NOW(), INTERVAL 24 HOUR)"); 
$events24 = xtc_db_fetch_array($q);

$q = xtc_db_query("SELECT COUNT(DISTINCT ip_address) AS total FROM msec_events WHERE date_added >= DATE_SUB(NOW(), INTERVAL 24 HOUR)"); 
$ips24 = xtc_db_fetch_array($q);

$q = xtc_db_query("SELECT COUNT(*) AS total FROM msec_events WHERE is_blocked = 1 AND date_added >= DATE_SUB(NOW(), INTERVAL 24 HOUR)"); 
$blocked24 = xtc_db_fetch_array($q);

$q = xtc_db_query("SELECT COUNT(*) AS total FROM msec_blocks WHERE is_permanent = 1 OR blocked_until IS NULL OR blocked_until > NOW()"); 
$activeblocks = xtc_db_fetch_array($q);

$events10n = (int)$events10['total']; 
$events1hn = (int)$events1h['total'];
$alerts    = array();

$burst = xtc_db_query("SELECT ip_address,COUNT(*) AS hits FROM msec_events WHERE date_added>=DATE_SUB(NOW(),INTERVAL 15 MINUTE) GROUP BY ip_address HAVING COUNT(*)>=5 ORDER BY hits DESC LIMIT 10");

while( $r = xtc_db_fetch_array($burst) ) {
    $alerts[]=array('high'  => (int)$r['hits']>=10,
                    'title' => BX_SECURITY_MONITOR_BURST_FROM_IP,
                    'text'  => sprintf(BX_SECURITY_MONITOR_BURST_FROM_IP_TEXT, $r['ip_address'], (int)$r['hits']));
}

$dist = xtc_db_query("SELECT request_path, COUNT(DISTINCT ip_address) AS ips FROM msec_events WHERE date_added>=DATE_SUB(NOW(),INTERVAL 1 HOUR) AND request_path!='' GROUP BY request_path HAVING COUNT(DISTINCT ip_address)>=5 ORDER BY ips DESC LIMIT 10");

while( $r = xtc_db_fetch_array($dist)) {
    $alerts[]=array('high'  => (int)$r['ips']>=10,
                    'title' => BX_SECURITY_MONITOR_DISTRIBUTED_SCAN,
                    'text'  => sprintf(BX_SECURITY_MONITOR_DISTRIBUTED_SCAN_TEXT, (int)$r['ips'], $r['request_path'])
    );
}

if( $events10n >= 20 || count($alerts)>=3) {
    $level = 'high';
    $label = BX_SECURITY_MONITOR_HIGH_SCANNER_ACTIVITY;
    $state = BX_SECURITY_MONITOR_HIGH_SCANNER_ACTIVITY_NOTE;
} elseif($events1hn>=5 || count($alerts)>0) {
    $level = 'medium';
    $label = BX_SECURITY_MONITOR_MEDIUM_SCANNER_ACTIVITY;
    $state = BX_SECURITY_MONITOR_MEDIUM_SCANNER_ACTIVITY_NOTE;
} else { 
    $level='low';
    $label = BX_SECURITY_MONITOR_LOW_SCANNER_ACTIVITY;
    $state = BX_SECURITY_MONITOR_LOW_SCANNER_ACTIVITY_NOTE;
}

$categories = array();
$cat_total  = 0;
$cq = xtc_db_query("SELECT category,COUNT(*) AS total, SUM(is_blocked) AS blocked FROM msec_events WHERE date_added>=DATE_SUB(NOW(),INTERVAL 24 HOUR) GROUP BY category ORDER BY total DESC");

while( $r = xtc_db_fetch_array($cq) ) {
    $r['category'] = $r['category'] != '' ? $r['category'] : 'Sonstige';
    $categories[]  = $r;
    $cat_total += (int)$r['total'];
}

$attackers = array();
$aq = xtc_db_query("SELECT ip_address,COUNT(*) AS hits,SUM(score) AS score,SUM(is_blocked) AS blocked,MAX(date_added) AS last_seen FROM msec_events WHERE date_added >= DATE_SUB(NOW(),INTERVAL 24 HOUR) GROUP BY ip_address ORDER BY hits DESC,score DESC LIMIT 10");

while( $r = xtc_db_fetch_array($aq) ) {
    $attackers[] = $r;
}

$targets = array();
$tq = xtc_db_query("SELECT request_path,reason,COUNT(*) AS hits,COUNT(DISTINCT ip_address) AS ips FROM msec_events WHERE date_added>=DATE_SUB(NOW(),INTERVAL 24 HOUR) AND request_path!='' GROUP BY request_path,reason ORDER BY hits DESC,ips DESC LIMIT 10");

while( $r = xtc_db_fetch_array($tq) ) {
    $targets[] = $r;
}

$critical = array();
$crq = xtc_db_query("SELECT * FROM msec_events WHERE is_blocked=1 OR score>=25 ORDER BY date_added DESC LIMIT 25");

while( $r = xtc_db_fetch_array($crq) ) {
    $critical[] = $r;
}

$hourly = array();
for( $i = 23; $i >= 0; $i--) { 
    $k = date('Y-m-d H:00:00',strtotime('-'.$i.' hour'));
    $hourly[$k] = array('label'=>date('H:00',strtotime($k)),'total' => 0);
}

$hq = xtc_db_query("SELECT DATE_FORMAT(date_added,'%Y-%m-%d %H:00:00') AS h, COUNT(*) AS total FROM msec_events WHERE date_added >= DATE_SUB(NOW(), INTERVAL 24 HOUR) GROUP BY DATE_FORMAT(date_added,'%Y-%m-%d %H:00:00')");

while( $r = xtc_db_fetch_array($hq)) {
    if(isset($hourly[$r['h']])) {
        $hourly[$r['h']]['total']=(int)$r['total'];
    }
}
$hourmax = 1;
foreach($hourly as $h) {
    $hourmax = max($hourmax,$h['total']);
}

$action = 'default';
$allowed_actions = array('save_settings', 
                         'add_rule', 
                         'delete_rule', 
                         'toggle_rule', 
                         'unblock', 
                         'add_whitelist', 
                         'whitelist_current', 
                         'block_to_whitelist', 
                         'delete_whitelist', 
                         'clear_events', 
                         'clear_expired');

if (isset($_GET['action']) && in_array((string)$_GET['action'], $allowed_actions, true)) {
    $action = (string)$_GET['action'];
}

$anker = $_POST['scroll_to'] ?? '';
$anker = preg_replace('/[^a-zA-Z0-9_-]/', '', $anker); // absichern!
// Whitelist: nur bekannte Formular-IDs erlauben
$permitted_anker_exact = ['bx_settings',
                          'bx_manual_rules',
                          'bx_auto_blocks',
                          'bx_permanent_whitelist',
                          'bx_events',
                         ];

$valid_anker = in_array($anker, $permitted_anker_exact, true);

if (!$valid_anker) {
    $anker = '';
}

$anker_url = xtc_href_link(FILENAME_BX_SECURITY_MONITOR, '', 'SSL');

if ($anker !== '') {
    $anker_url = xtc_href_link(FILENAME_BX_SECURITY_MONITOR, 'scroll_to=' . urlencode($anker), 'SSL');
}

switch($action) {
    case 'save_settings':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            $messageStack->add_session(BX_SECURITY_MONITOR_INVALID_SAVE_CALL, 'warning');
            xtc_redirect($anker_url);
        }

        $scannerStatus = 'True';
        if (isset($_POST['MODULE_BX_SECURITY_SCANNER_STATUS']) && in_array((string)$_POST['MODULE_BX_SECURITY_SCANNER_STATUS'], array('True', 'False'), true)) {
            $scannerStatus = (string)$_POST['MODULE_BX_SECURITY_SCANNER_STATUS'];
        }

        $adminLoginStatus = 'True';
        if (isset($_POST['MODULE_BX_SECURITY_ADMIN_LOGIN_STATUS']) && in_array((string)$_POST['MODULE_BX_SECURITY_ADMIN_LOGIN_STATUS'], array('True', 'False'), true)) {
            $adminLoginStatus = (string)$_POST['MODULE_BX_SECURITY_ADMIN_LOGIN_STATUS'];
        }

        $settings = array(
            'MODULE_BX_SECURITY_SCANNER_STATUS'             => $scannerStatus,
            'MODULE_BX_SECURITY_ADMIN_LOGIN_STATUS'         => $adminLoginStatus,
            'MODULE_BX_SECURITY_BLOCK_THRESHOLD'            => max(10, min(100, (int)($_POST['MODULE_BX_SECURITY_BLOCK_THRESHOLD'] ?? 10))),
            'MODULE_BX_SECURITY_SCORE_WINDOW_MINUTES'       => max(1, min(1440, (int)($_POST['MODULE_BX_SECURITY_SCORE_WINDOW_MINUTES'] ?? 10))),
            'MODULE_BX_SECURITY_BLOCK_HOURS'                => max(1, min(8760, (int)($_POST['MODULE_BX_SECURITY_BLOCK_HOURS'] ?? 24))),
            'MODULE_BX_SECURITY_EVENT_RETENTION_DAYS'       => max(1, min(3650, (int)($_POST['MODULE_BX_SECURITY_EVENT_RETENTION_DAYS'] ?? 14))),
            'MODULE_BX_SECURITY_ADMIN_LOGIN_MAX_ATTEMPTS'   => max(3, min(1000, (int)($_POST['MODULE_BX_SECURITY_ADMIN_LOGIN_MAX_ATTEMPTS'] ?? 10))),
            'MODULE_BX_SECURITY_ADMIN_LOGIN_WINDOW_MINUTES' => max(1, min(1440, (int)($_POST['MODULE_BX_SECURITY_ADMIN_LOGIN_WINDOW_MINUTES'] ?? 15))),
            'MODULE_BX_SECURITY_ADMIN_LOGIN_BLOCK_MINUTES'  => max(1, min(10080, (int)($_POST['MODULE_BX_SECURITY_ADMIN_LOGIN_BLOCK_MINUTES'] ?? 60))),
        );

        foreach ($settings as $key => $value) {
            xtc_db_query("UPDATE " . TABLE_CONFIGURATION . " SET configuration_value = '" . xtc_db_prepare_input($value) . "', last_modified = NOW() WHERE configuration_key = '" . xtc_db_prepare_input($key) . "'");
        }

        $messageStack->add_session(BX_SECURITY_MONITOR_SETTINGS_SAVED, 'success');
        xtc_redirect($anker_url);
        break;
    
    case 'add_rule':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            $messageStack->add_session(BX_SECURITY_MONITOR_INVALID_ADD_RULE_CALL, 'warning');
            xtc_redirect($anker_url);
        }
        $pattern   = (string)($_POST['pattern'] ?? '');
        $matchType = (string)($_POST['match_type'] ?? '');
        $type      = in_array($matchType, array('exact', 'prefix', 'contains'), true) ? $matchType : 'contains';
        $score     = max(1, min(100, (int)($_POST['score'] ?? 0)));

        if ($pattern !== '') {
            xtc_db_query("INSERT INTO msec_manual_rules (pattern, 
                                                                match_type, 
                                                                score, 
                                                                is_enabled, 
                                                                hit_count, 
                                                                date_added) 
                                                        VALUES ('" . xtc_db_prepare_input($pattern) . "', 
                                                                '" . xtc_db_prepare_input($type) . "', 
                                                                '" . (int)$score . "', 
                                                                1, 
                                                                0, 
                                                                NOW())");
            msec_admin_rebuild_rule_cache();
        }

        $messageStack->add_session(BX_SECURITY_MONITOR_RULE_SAVED, 'success');
        xtc_redirect($anker_url);
        break;
    case 'delete_rule':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            $messageStack->add_session(BX_SECURITY_MONITOR_INVALID_DELETE_RULE_CALL, 'warning');
            xtc_redirect($anker_url);
        }
        $ruleId = (int)($_POST['rule_id'] ?? 0);
        if ($ruleId > 0) {
            xtc_db_query("DELETE FROM msec_manual_rules WHERE rule_id = '" . (int)$ruleId . "'");
            msec_admin_rebuild_rule_cache();
        }

        $messageStack->add_session(BX_SECURITY_MONITOR_RULE_DELETED, 'success');
        xtc_redirect($anker_url);
        break;
    case 'toggle_rule':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            $messageStack->add_session(BX_SECURITY_MONITOR_INVALID_TOGGLE_RULE_CALL, 'warning');
            xtc_redirect($anker_url);
        }
        $ruleId = (int)($_POST['rule_id'] ?? 0);
        if ($ruleId > 0) {
            $query = xtc_db_query("SELECT is_enabled FROM msec_manual_rules WHERE rule_id = '" . (int)$ruleId . "'");
            if ($row = xtc_db_fetch_array($query)) {
                $newStatus = $row['is_enabled'] ? 0 : 1;
                xtc_db_query("UPDATE msec_manual_rules SET is_enabled = '" . (int)$newStatus . "' WHERE rule_id = '" . (int)$ruleId . "'");
                msec_admin_rebuild_rule_cache();
            }
        }

        $messageStack->add_session(BX_SECURITY_MONITOR_STATUS_UPDATED, 'success');
        xtc_redirect($anker_url);
        break;
    case 'unblock':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            $messageStack->add_session(BX_SECURITY_MONITOR_INVALID_UNBLOCK_CALL, 'warning');
            xtc_redirect($anker_url);
        }
        xtc_db_query("DELETE FROM msec_blocks WHERE block_id = '" . (int)$_POST['block_id'] . "'");
        $messageStack->add_session(BX_SECURITY_MONITOR_ENTRY_UNBLOCKED, 'success');
        xtc_redirect($anker_url);
        break;
    case 'add_whitelist':
    case 'whitelist_current':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            $messageStack->add_session(BX_SECURITY_MONITOR_INVALID_ADD_WHITELIST_CALL, 'warning');
            xtc_redirect($anker_url);
        }
        if ($action === 'whitelist_current') {
            $ip   = isset($_SERVER['REMOTE_ADDR']) ? trim((string)$_SERVER['REMOTE_ADDR']) : '';
            $note = 'Aktuelle Admin-IP / VPN';
        } else {
            $ip   = trim((string)($_POST['ip_address'] ?? ''));
            $note = trim((string)($_POST['note'] ?? ''));
        }

        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            xtc_db_query("INSERT INTO msec_whitelist (ip_address, note, date_added) VALUES ('" . xtc_db_prepare_input($ip) . "', '" . xtc_db_prepare_input($note) . "', NOW()) ON DUPLICATE KEY UPDATE note = VALUES(note)");
            xtc_db_query("DELETE FROM msec_blocks WHERE ip_address = '" . xtc_db_prepare_input($ip) . "'");
        }
        bx_sync_whitelist_file();
        $messageStack->add_session(BX_SECURITY_MONITOR_LIST_UPDATED, 'success');
        xtc_redirect($anker_url);
        break;
    case 'block_to_whitelist':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            $messageStack->add_session(BX_SECURITY_MONITOR_INVALID_BLOCK_TO_WHITELIST_CALL, 'warning');
            xtc_redirect($anker_url);
        }
        $ip = trim((string)$_POST['ip_address']);
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            xtc_db_query("INSERT INTO msec_whitelist (ip_address, note, date_added) VALUES ('" . xtc_db_prepare_input($ip) . "', 'Aus automatischer Sperre übernommen', NOW()) ON DUPLICATE KEY UPDATE note = VALUES(note)");
            xtc_db_query("DELETE FROM msec_blocks WHERE ip_address = '" . xtc_db_prepare_input($ip) . "'");
        }
        bx_sync_whitelist_file();
        $messageStack->add_session(BX_SECURITY_MONITOR_ENTRY_TAKEN_OVER, 'success');
        xtc_redirect($anker_url);
        break;
    case 'delete_whitelist':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            $messageStack->add_session(BX_SECURITY_MONITOR_INVALID_DELETE_WHITELIST_CALL, 'warning');
            xtc_redirect($anker_url);
        }
        $whitelist_id = (int)($_POST['whitelist_id'] ?? 0);
        if ($whitelist_id > 0) {
            xtc_db_query("DELETE FROM msec_whitelist WHERE whitelist_id = '" . $whitelist_id. "'");
        }
        bx_sync_whitelist_file();
        $messageStack->add_session(BX_SECURITY_MONITOR_WHITELIST_ENTRY_DELETED, 'success');
        xtc_redirect($anker_url);
        break;
    case 'clear_events':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            $messageStack->add_session(BX_SECURITY_MONITOR_INVALID_CLEAR_EVENTS_CALL, 'warning');
            xtc_redirect($anker_url);
        }
        xtc_db_query("DELETE FROM msec_events");
        $messageStack->add_session(BX_SECURITY_MONITOR_EVENTS_CLEARED, 'success');
        xtc_redirect($anker_url);
        break;
    case 'clear_expired':
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            $messageStack->add_session(BX_SECURITY_MONITOR_INVALID_CLEAR_EXPIRED_CALL, 'warning');
            xtc_redirect($anker_url);
        }
        xtc_db_query("DELETE FROM msec_blocks WHERE blocked_until < NOW()");
        $messageStack->add_session(BX_SECURITY_MONITOR_EXPIRED_BLOCKS_CLEARED, 'success');
        xtc_redirect($anker_url);
        break;
    default:
        /* Do nothing */
        break;
}

$check_fn = 'msec_check_patch_status';

// Check if the login_admin.php patch is applied
$admin_patch_status = function_exists($check_fn)
    ? $check_fn(DIR_FS_CATALOG . 'login_admin.php', DIR_FS_CATALOG . 'login_admin.php.bx-backup')
    : 'unknown';

// Check if the xss_secure.php patch is applied
$xss_patch_status = function_exists($check_fn)
    ? $check_fn(DIR_FS_CATALOG . 'includes/xss_secure.php', DIR_FS_CATALOG . 'includes/xss_secure.php.bx-backup')
    : 'unknown';

require_once (DIR_WS_INCLUDES.'head.php');

$messageStack->output();
?>
</head>
<!-- header //-->
<?php require(DIR_WS_INCLUDES.'header.php'); ?>

<!-- header_eof //-->
<!-- body //-->
<table class="tableBody">
  <tr>
    <?php //left_navigation
    if (USE_ADMIN_TOP_MENU == 'false') {
      echo '<td class="columnLeft2">'.PHP_EOL;
      echo '<!-- left_navigation //-->'.PHP_EOL;
      require_once(DIR_WS_INCLUDES.'column_left.php');
      echo '<!-- left_navigation eof //-->'.PHP_EOL;
      echo '</td>'.PHP_EOL;
    }
    ?>
    <!-- body_text //-->
    <td class="boxCenter">
      <div class="pageHeadingImage" style="width: 42px;">
        <?php echo xtc_image(DIR_WS_ICONS.'heading/bx-security-monitor.png', BX_SECURITY_MONITOR_TITLE_TAG, '', '', 'style="height: 40px;"'); ?>
      </div>
      <div class="pageHeading flt-l">
        <?php echo BX_SECURITY_MONITOR_TITLE; ?>
        <div class="main">
          <?php echo BX_SECURITY_MONITOR_DESCRIPTION; ?>
        </div>
      </div>

      <div class="pageHeading flt-r">
        <?php
            msec_render_patch_status($xss_patch_status, [
                'mismatch'       => BX_SECURITY_MONITOR_XSS_SECURE_PHP_PATCH_MISMATCH,
                'target_missing' => BX_SECURITY_MONITOR_XSS_SECURE_PHP_TARGET_MISSING,
                'meta_missing'   => BX_SECURITY_MONITOR_XSS_SECURE_PHP_META_MISSING,
                'meta_invalid'   => BX_SECURITY_MONITOR_XSS_SECURE_PHP_META_INVALID,
                'not_installed'  => BX_SECURITY_MONITOR_XSS_SECURE_PHP_NOT_INSTALLED,
                'ok'             => BX_SECURITY_MONITOR_XSS_SECURE_PHP_OK,
                'unknown'        => BX_SECURITY_MONITOR_XSS_SECURE_PHP_STATUS_UNKNOWN,
            ]);
        ?>
      </div>

      <div class="pageHeading flt-r">
          <?php
            msec_render_patch_status($admin_patch_status, [
                'mismatch'       => BX_SECURITY_MONITOR_LOGIN_ADMIN_PHP_PATCH_MISMATCH,
                'target_missing' => BX_SECURITY_MONITOR_LOGIN_ADMIN_PHP_TARGET_MISSING,
                'meta_missing'   => BX_SECURITY_MONITOR_LOGIN_ADMIN_PHP_META_MISSING,
                'meta_invalid'   => BX_SECURITY_MONITOR_LOGIN_ADMIN_PHP_META_INVALID,
                'not_installed'  => BX_SECURITY_MONITOR_LOGIN_ADMIN_PHP_NOT_INSTALLED,
                'ok'             => BX_SECURITY_MONITOR_LOGIN_ADMIN_PHP_OK,
                'unknown'        => BX_SECURITY_MONITOR_LOGIN_ADMIN_PHP_STATUS_UNKNOWN,
            ]);
          ?>
      </div>

      <div class="clear"></div>

      <table class="tableCenter" style="margin-top: 5px;">
        <tr>
          <td class="boxCenterLeft">

            <div id="headboard">
              <div class="main">
                <?php echo BX_SECURITY_MONITOR_TITLE_NOTE; ?>
              </div>
            </div>

            <div class="boxCenter">
              <div class="msec-state msec-state-<?php echo msec_admin_h($level); ?>">
                  <small><?php echo BX_SECURITY_MONITOR_TXT_CURRENT_ACTIVITY; ?></small><strong><?php echo msec_admin_h($label); ?></strong><?php echo msec_admin_h($state); ?>
              </div>

              <div class="msec-cards">
                  <div class="msec-card"><div class="msec-card-label"><?php echo BX_SECURITY_MONITOR_HITS_10_MIN; ?></div><div class="msec-card-value"><?php echo (int)$events10['total']; ?></div></div>
                  <div class="msec-card"><div class="msec-card-label"><?php echo BX_SECURITY_MONITOR_HITS_1_HOUR; ?></div><div class="msec-card-value"><?php echo (int)$events1h['total']; ?></div></div>
                  <div class="msec-card"><div class="msec-card-label"><?php echo BX_SECURITY_MONITOR_HITS_24_HOURS; ?></div><div class="msec-card-value"><?php echo (int)$events24['total']; ?></div></div>
                  <div class="msec-card"><div class="msec-card-label"><?php echo BX_SECURITY_MONITOR_IPS_24_HOURS; ?></div><div class="msec-card-value"><?php echo (int)$ips24['total']; ?></div></div>
                  <div class="msec-card"><div class="msec-card-label"><?php echo BX_SECURITY_MONITOR_BLOCKED_EVENTS; ?></div><div class="msec-card-value"><?php echo (int)$blocked24['total']; ?></div></div>
                  <div class="msec-card"><div class="msec-card-label"><?php echo BX_SECURITY_MONITOR_ACTIVE_IP_BLOCKS; ?></div><div class="msec-card-value"><?php echo (int)$activeblocks['total']; ?></div></div>
              </div>

              <div class="msec-grid">
                  <div class="msec-box main">
                      <div class="msec-box-title pastel-apricot"><?php echo BX_SECURITY_MONITOR_UNUSUAL_ACTIVITY; ?></div>
                      <div class="msec-box-body">
                      <?php if(count($alerts)<1){ ?><div class="msec-info" style="margin:0"><?php echo BX_SECURITY_MONITOR_NO_UNUSUAL_ACTIVITY; ?></div><?php } ?>
                      <?php foreach($alerts as $a){ ?>
                      <div class="msec-alert<?php echo $a['high']?' high':''; ?>">
                          <strong><?php echo msec_admin_h($a['title']); ?></strong>
                          <div class="msec-small">
                              <?php echo msec_admin_h($a['text']); ?>
                          </div>
                      </div>
                      <?php } ?>
                      </div>
                  </div>
                  <div class="msec-box main">
                      <div class="msec-box-title pastel-mint"><?php echo BX_SECURITY_MONITOR_DETECTED_ATTACK_TYPES_24_HOURS; ?></div>
                      <div class="msec-box-body">
                          <?php if(count($categories)<1){echo BX_SECURITY_MONITOR_NO_EVENTS; } ?>
                          <?php
                              foreach($categories as $c) {
                                  $p = $cat_total > 0 ? round(((int)$c['total']/$cat_total)*100,1):0; ?>
                                  <div class="msec-bars-row">
                                      <strong class="msec-small"><?php echo msec_admin_h($c['category']); ?></strong>
                                      <div class="msec-bar-track">
                                          <div class="msec-bar" style="width:<?php echo max(2,min(100,$p)); ?>%"></div>
                                      </div>
                                      <strong><?php echo (int)$c['total']; ?></strong>
                                  </div>
                          <?php } ?>
                      </div>
                  </div>
              </div>

              <div class="msec-box main">
                <div class="msec-box-title pastel-sky">
                    <?php echo BX_SECURITY_MONITOR_ACTIVITY_OVERVIEW_24_HOURS; ?>
                </div>
                <div class="msec-box-body">
                    <div class="msec-chart">
                    <?php 
                    $idx = 0;
                    foreach($hourly as $h) { 
                        $height = max(2,round(($h['total']/$hourmax)*135)); ?>
                        <div class="msec-chart-col" title="<?php echo msec_admin_h($h['label'].': '.$h['total'].' Treffer'); ?>">
                        <?php if($h['total'] > 0) { ?>
                            <div class="msec-chart-value">
                            <?php echo (int)$h['total']; ?>
                            </div>
                        <?php } ?>
                            <div class="msec-chart-bar" style="height:<?php echo (int)$height; ?>px"></div>
                            <div class="msec-chart-label"><?php echo ($idx % 3 === 0) ? msec_admin_h($h['label']) : ''; ?></div>
                        </div>
                    <?php 
                        $idx++;
                    }
                    ?>
                    </div>
                </div>
              </div>

              <div class="msec-grid">
                  <div class="msec-box main">
                      <div class="msec-box-title pastel-lavender"><?php echo BX_SECURITY_MONITOR_TOP_ATTACKING_IPS_24_HOURS; ?></div>
                      <div class="msec-box-body">
                          <table class="msec-table">
                              <thead>
                                  <tr>
                                      <th><?php echo BX_SECURITY_MONITOR_TH_IP; ?></th>
                                      <th><?php echo BX_SECURITY_MONITOR_TH_HITS; ?></th>
                                      <th><?php echo BX_SECURITY_MONITOR_TH_SCORE; ?></th>
                                      <th><?php echo BX_SECURITY_MONITOR_TH_BLOCKED; ?></th>
                                      <th><?php echo BX_SECURITY_MONITOR_TH_LAST_SEEN; ?></th>
                                  </tr>
                              </thead>
                              <tbody>
                                  <?php
                                  if(count($attackers) < 1) {
                                      echo '<tr>
                                      <td colspan="5">' . BX_SECURITY_MONITOR_NO_EVENTS . '</td>
                                      </tr>';
                                  }
                                  foreach( $attackers as $r) { ?>
                                  <tr>
                                      <td><?php echo msec_admin_h($r['ip_address']); ?></td>
                                      <td><?php echo (int)$r['hits']; ?></td>
                                      <td><?php echo (int)$r['score']; ?></td>
                                      <td><?php echo (int)$r['blocked']; ?></td>
                                      <td><?php echo msec_admin_h($r['last_seen']); ?></td>
                                  </tr>
                                  <?php } ?>
                              </tbody>
                          </table>
                      </div>
                  </div>
                  <div class="msec-box main">
                      <div class="msec-box-title pastel-rose"><?php echo BX_SECURITY_MONITOR_MOST_ATTACKED_PATHS_24_HOURS; ?></div>
                      <div class="msec-box-body">
                          <table class="msec-table">
                              <thead>
                                  <tr>
                                      <th><?php echo BX_SECURITY_MONITOR_TH_PATH; ?></th>
                                      <th><?php echo BX_SECURITY_MONITOR_TH_REASON; ?></th>
                                      <th><?php echo BX_SECURITY_MONITOR_TH_HITS; ?></th>
                                      <th><?php echo BX_SECURITY_MONITOR_TH_IPS; ?></th>
                                  </tr>
                              </thead>
                              <tbody>
                                  <?php
                                  if(count($targets) < 1){
                                      echo '<tr>
                                      <td colspan="4">' . BX_SECURITY_MONITOR_NO_EVENTS . '</td>
                                      </tr>';
                                  }
                                  foreach($targets as $r) { ?>
                                  <tr>
                                      <td class="msec-path"><?php echo msec_admin_h(msec_admin_short($r['request_path'],65)); ?></td>
                                      <td><?php echo msec_admin_h(msec_admin_short($r['reason'],60)); ?></td>
                                      <td><?php echo (int)$r['hits']; ?></td>
                                      <td><?php echo (int)$r['ips']; ?></td>
                                  </tr>
                                  <?php } ?>
                              </tbody>
                          </table>
                      </div>
                  </div>
              </div>

              <div class="msec-box main">
                  <div class="msec-box-title pastel-lemon"><?php echo BX_SECURITY_MONITOR_LAST_CRITICAL_OR_BLOCKED_EVENTS; ?></div>
                  <div class="msec-box-body">
                      <table class="msec-table">
                          <thead>
                              <tr>
                                  <th><?php echo BX_SECURITY_MONITOR_TH_TIME; ?></th>
                                  <th><?php echo BX_SECURITY_MONITOR_TH_IP; ?></th>
                                  <th><?php echo BX_SECURITY_MONITOR_TH_METHOD; ?></th>
                                  <th><?php echo BX_SECURITY_MONITOR_TH_PATH; ?></th>
                                  <th><?php echo BX_SECURITY_MONITOR_TH_CATEGORY; ?></th>
                                  <th><?php echo BX_SECURITY_MONITOR_TH_REASON; ?></th>
                                  <th><?php echo BX_SECURITY_MONITOR_TH_SCORE; ?></th>
                                  <th><?php echo BX_SECURITY_MONITOR_TH_STATUS; ?></th>
                              </tr>
                          </thead>
                          <tbody>
                          <?php
                          if(count($critical) <1 ) {
                              echo '<tr><td colspan="8">' . BX_SECURITY_MONITOR_NO_CRITICAL_EVENTS . '</td></tr>';
                          }
                          foreach($critical as $r){ ?>
                              <tr>
                                  <td><?php echo msec_admin_h($r['date_added']); ?></td>
                                  <td><?php echo msec_admin_h($r['ip_address']); ?></td>
                                  <td><?php echo msec_admin_h($r['request_method']); ?></td>
                                  <td class="msec-path"><?php echo msec_admin_h(msec_admin_short($r['request_path'],70)); ?></td>
                                  <td><?php echo msec_admin_h($r['category']); ?></td>
                                  <td><?php echo msec_admin_h(msec_admin_short($r['reason'],80)); ?></td>
                                  <td><?php echo (int)$r['score']; ?></td>
                                  <td><span class="msec-badge <?php echo (int)$r['is_blocked']===1?'msec-badge-red':'msec-badge-grey'; ?>"><?php echo (int)$r['is_blocked']===1?'blockiert':'kritisch'; ?></span></td>
                              </tr>
                          <?php } ?>
                          </tbody>
                      </table>
                  </div>
              </div>

              <div class="msec-box main">
                  <div class="msec-box-title pastel-apricot scroll-target" id="bx_settings"><?php echo BX_SECURITY_MONITOR_SETTINGS; ?></div>
                  <div class="msec-box-body">
                    <?php
                    echo xtc_draw_form('bx_security_monitor_form', FILENAME_BX_SECURITY_MONITOR, 'action=save_settings');
                    echo xtc_draw_hidden_field('scroll_to', 'bx_settings');
                    ?>
                      <div class="msec-settings">
                          <div>
                              <label for="MODULE_BX_SECURITY_SCANNER_STATUS">Scanner-Erkennung</label>
                              <?php
                                $statusSelectData = array(
                                    array('id' => 'True',  'text' => BX_SECURITY_MONITOR_ACTIVE),
                                    array('id' => 'False', 'text' => BX_SECURITY_MONITOR_INACTIVE),
                                );
                              echo xtc_draw_pull_down_menu('MODULE_BX_SECURITY_SCANNER_STATUS', $statusSelectData, MODULE_BX_SECURITY_SCANNER_STATUS, 'id="MODULE_BX_SECURITY_SCANNER_STATUS"'); ?>
                          </div>
                          <div>
                              <label for="MODULE_BX_SECURITY_BLOCK_THRESHOLD"><?php echo BX_SECURITY_MONITOR_BLOCK_THRESHOLD; ?></label>
                              <?php echo xtc_draw_input_field('MODULE_BX_SECURITY_BLOCK_THRESHOLD', (int)MODULE_BX_SECURITY_BLOCK_THRESHOLD, 'min="10" max="100" id="MODULE_BX_SECURITY_BLOCK_THRESHOLD"', false, 'number'); ?>
                          </div>
                          <div>
                              <label for="MODULE_BX_SECURITY_SCORE_WINDOW_MINUTES"><?php echo BX_SECURITY_MONITOR_SCORE_WINDOW_MINUTES; ?></label>
                              <?php echo xtc_draw_input_field('MODULE_BX_SECURITY_SCORE_WINDOW_MINUTES', (int)MODULE_BX_SECURITY_SCORE_WINDOW_MINUTES, 'min="1" max="1440" id="MODULE_BX_SECURITY_SCORE_WINDOW_MINUTES"', false, 'number'); ?>
                          </div>
                          <div>
                              <label for="MODULE_BX_SECURITY_BLOCK_HOURS"><?php echo BX_SECURITY_MONITOR_BLOCK_HOURS; ?></label>
                              <?php echo xtc_draw_input_field('MODULE_BX_SECURITY_BLOCK_HOURS', (int)MODULE_BX_SECURITY_BLOCK_HOURS, 'min="1" max="8760" id="MODULE_BX_SECURITY_BLOCK_HOURS"', false, 'number'); ?>
                          </div>
                          <div>
                              <label for="MODULE_BX_SECURITY_EVENT_RETENTION_DAYS"><?php echo BX_SECURITY_MONITOR_EVENT_RETENTION_DAYS; ?></label>
                              <?php echo xtc_draw_input_field('MODULE_BX_SECURITY_EVENT_RETENTION_DAYS', (int)MODULE_BX_SECURITY_EVENT_RETENTION_DAYS, 'min="1" max="3650" id="MODULE_BX_SECURITY_EVENT_RETENTION_DAYS"', false, 'number'); ?>
                          </div>
                      </div>
                      <hr style="background: #aaa; height: 2px; margin: 1rem 0; border: none;">
                      <div class="msec-settings">
                          <div>
                              <label for="MODULE_BX_SECURITY_ADMIN_LOGIN_STATUS"><?php echo BX_SECURITY_MONITOR_ADMIN_LOGIN_STATUS; ?></label>
                              <?php echo xtc_draw_pull_down_menu('MODULE_BX_SECURITY_ADMIN_LOGIN_STATUS', $statusSelectData, MODULE_BX_SECURITY_ADMIN_LOGIN_STATUS, 'id="MODULE_BX_SECURITY_ADMIN_LOGIN_STATUS"'); ?>
                          </div>
                          <div>
                              <label for="MODULE_BX_SECURITY_ADMIN_LOGIN_MAX_ATTEMPTS"><?php echo BX_SECURITY_MONITOR_ADMIN_LOGIN_MAX_ATTEMPTS; ?></label>
                              <?php echo xtc_draw_input_field('MODULE_BX_SECURITY_ADMIN_LOGIN_MAX_ATTEMPTS', (int)MODULE_BX_SECURITY_ADMIN_LOGIN_MAX_ATTEMPTS, 'min="3" max="1000" id="MODULE_BX_SECURITY_ADMIN_LOGIN_MAX_ATTEMPTS"', false, 'number'); ?>
                          </div>
                          <div>
                              <label for="MODULE_BX_SECURITY_ADMIN_LOGIN_WINDOW_MINUTES"><?php echo BX_SECURITY_MONITOR_ADMIN_LOGIN_WINDOW_MINUTES; ?></label>
                              <?php echo xtc_draw_input_field('MODULE_BX_SECURITY_ADMIN_LOGIN_WINDOW_MINUTES', (int)MODULE_BX_SECURITY_ADMIN_LOGIN_WINDOW_MINUTES, 'min="1" max="1440" id="MODULE_BX_SECURITY_ADMIN_LOGIN_WINDOW_MINUTES"', false, 'number'); ?>
                          </div>
                          <div>
                              <label for="MODULE_BX_SECURITY_ADMIN_LOGIN_BLOCK_MINUTES"><?php echo BX_SECURITY_MONITOR_ADMIN_LOGIN_BLOCK_MINUTES; ?></label>
                              <?php echo xtc_draw_input_field('MODULE_BX_SECURITY_ADMIN_LOGIN_BLOCK_MINUTES', (int)MODULE_BX_SECURITY_ADMIN_LOGIN_BLOCK_MINUTES, 'min="1" max="10080" id="MODULE_BX_SECURITY_ADMIN_LOGIN_BLOCK_MINUTES"', false, 'number'); ?>
                          </div>
                      </div>
                      <br>
                      <button class="msec-button" type="submit"><?php echo BX_SECURITY_MONITOR_SAVE_SETTINGS; ?></button>
                    </form>
                  </div>
              </div>

                            <div class="msec-box main">
                                <div class="msec-box-title pastel-mint scroll-target" id="bx_manual_rules"><?php echo BX_SECURITY_MONITOR_MANUAL_RULES; ?></div>
                <div class="msec-box-body">
                    <div class="msec-warning">
                                            <?php echo BX_SECURITY_MONITOR_MANUAL_RULES_WARNING; ?>
                    </div>

                    <?php 
                    echo xtc_draw_form('manual_rules_form', FILENAME_BX_SECURITY_MONITOR, 'action=add_rule');
                    echo xtc_draw_hidden_field('scroll_to', 'bx_manual_rules');
                    ?>
                      <div class="msec-form-row">
                        <div>
                            <label for="pattern"><?php echo BX_SECURITY_MONITOR_PATTERN; ?></label>
                            <?php echo xtc_draw_input_field('pattern', '', 'id="pattern" required placeholder="/.secret-path"'); ?>
                        </div>
                        <div>
                            <label for="match_type"><?php echo BX_SECURITY_MONITOR_COMPARISON; ?></label>
                            <?php 
                            $matchTypesData = array(
                                array('id' => 'prefix',   'text' => BX_SECURITY_MONITOR_MATCH_PREFIX),
                                array('id' => 'exact',    'text' => BX_SECURITY_MONITOR_MATCH_EXACT),
                                array('id' => 'contains', 'text' => BX_SECURITY_MONITOR_MATCH_CONTAINS),
                            );
                            echo xtc_draw_pull_down_menu('match_type', $matchTypesData, 'prefix', 'id="match_type"');
                            ?>
                        </div>
                        <div>
                            <label for="score"><?php echo BX_SECURITY_MONITOR_TH_SCORE; ?></label>
                            <?php echo xtc_draw_input_field('score', '25', 'min="1" max="100" id="score"', false, 'number'); ?>
                        </div>
                        <div>
                            <button class="msec-button" type="submit" style="margin-top: 18px;"><?php echo BX_SECURITY_MONITOR_ADD_RULE; ?></button>
                        </div>
                      </div>
                    </form>
                    <br>
                    <table class="msec-table">
                        <thead>
                            <tr>
                                <th><?php echo BX_SECURITY_MONITOR_PATTERN; ?></th>
                                <th><?php echo BX_SECURITY_MONITOR_COMPARISON; ?></th>
                                <th><?php echo BX_SECURITY_MONITOR_TH_SCORE; ?></th>
                                <th><?php echo BX_SECURITY_MONITOR_TH_STATUS; ?></th>
                                <th><?php echo BX_SECURITY_MONITOR_TH_ACTION; ?></th>
                            </tr>
                        </thead>
                        <tbody>
                        <?php 
                        $rq = xtc_db_query("SELECT * FROM msec_manual_rules ORDER BY rule_id DESC");
                        
                        if(xtc_db_num_rows($rq) < 1) {
                            echo '<tr><td colspan="5">' . BX_SECURITY_MONITOR_NO_MANUAL_RULES . '</td></tr>';
                        }
                        $form_id = 0;
                        while($r = xtc_db_fetch_array($rq)) { ?>
                            <tr>
                                <td class="msec-path"><?php echo msec_admin_h($r['pattern']); ?></td>
                                <td><?php echo msec_admin_h($r['match_type']); ?></td>
                                <td><?php echo (int)$r['score']; ?></td>
                                <td><span class="msec-badge <?php echo (int)$r['is_enabled']===1?'msec-badge-green':'msec-badge-grey'; ?>"><?php echo (int)$r['is_enabled']===1?BX_SECURITY_MONITOR_ACTIVE:BX_SECURITY_MONITOR_INACTIVE; ?></span></td>
                                <td class="msec-actions">
                                <?php 
                                    echo xtc_draw_form('toggle_rule_form_' . $form_id, FILENAME_BX_SECURITY_MONITOR, 'action=toggle_rule', 'post', 'onsubmit="return confirm(\'' . BX_SECURITY_MONITOR_CONFIRM_TOGGLE_RULE_STATUS . '\');"');
                                    echo xtc_draw_hidden_field('rule_id', (int)$r['rule_id']);
                                    echo xtc_draw_hidden_field('scroll_to', 'bx_manual_rules');
                                ?>
                                    <button class="secondary" type="submit"><?php echo BX_SECURITY_MONITOR_TOGGLE; ?></button>
                                    </form>
                                    
                                <?php
                                    echo  xtc_draw_form('delete_rule_form_' . $form_id, FILENAME_BX_SECURITY_MONITOR, 'action=delete_rule', 'post', 'onsubmit="return confirm(\'' . BX_SECURITY_MONITOR_CONFIRM_DELETE_RULE . '\');"');
                                    echo xtc_draw_hidden_field('rule_id', (int)$r['rule_id']);
                                    echo xtc_draw_hidden_field('scroll_to', 'bx_manual_rules');
                                ?>
                                    <button type="submit"><?php echo BX_SECURITY_MONITOR_DELETE; ?></button>
                                    </form>
                                </td>
                            </tr>
                        <?php
                            $form_id++;
                        }
                        ?>
                        </tbody>
                    </table>
                </div>
              </div>

              <div class="msec-box main">
                  <div class="msec-box-title pastel-sky scroll-target" id="bx_auto_blocks"><?php echo BX_SECURITY_MONITOR_ACTIVE_AUTO_BLOCKS; ?></div>
                  <div class="msec-box-body">
                      <div class="msec-actions" style="justify-content:flex-end">
                        <?php
                        echo xtc_draw_form('clear_expired_form', FILENAME_BX_SECURITY_MONITOR, 'action=clear_expired');
                        echo xtc_draw_hidden_field('scroll_to', 'bx_auto_blocks');
                        ?>
                                                    <button class="light" type="submit" style="margin-bottom: 10px;"><?php echo BX_SECURITY_MONITOR_DELETE_EXPIRED_ENTRIES; ?></button>
                        </form>
                      </div>
                      <table class="msec-table">
                          <thead>
                              <tr>
                                  <th><?php echo BX_SECURITY_MONITOR_TH_IP; ?></th>
                                  <th><?php echo BX_SECURITY_MONITOR_TH_REASON; ?></th>
                                  <th><?php echo BX_SECURITY_MONITOR_TH_SCORE; ?></th>
                                  <th><?php echo BX_SECURITY_MONITOR_TH_HITS; ?></th>
                                  <th><?php echo BX_SECURITY_MONITOR_TH_BLOCKED_UNTIL; ?></th>
                                  <th><?php echo BX_SECURITY_MONITOR_TH_ACTION; ?></th>
                              </tr>
                          </thead>
                          <tbody>
                          <?php
                          $bq = xtc_db_query("SELECT * FROM msec_blocks WHERE is_permanent = 1 OR blocked_until IS NULL OR blocked_until > NOW() ORDER BY last_seen DESC LIMIT 200");
                          if(xtc_db_num_rows($bq) < 1) { 
                              echo '<tr><td colspan="6">' . BX_SECURITY_MONITOR_NO_ACTIVE_BLOCKS . '</td></tr>';
                          }
                          $form_id = 0;
                          while($r = xtc_db_fetch_array($bq)) { ?>
                              <tr>
                                  <td><?php echo msec_admin_h($r['ip_address']); ?></td>
                                  <td><?php echo msec_admin_h(msec_admin_short($r['reason'],100)); ?></td>
                                  <td><?php echo (int)$r['score']; ?></td>
                                  <td><?php echo (int)$r['hits']; ?></td>
                                  <td><?php echo (int)$r['is_permanent']===1?BX_SECURITY_MONITOR_PERMANENT:msec_admin_h($r['blocked_until']); ?></td>
                                  <td class="msec-actions">
                                    <?php
                                    echo xtc_draw_form('unblock_form_' . $form_id, FILENAME_BX_SECURITY_MONITOR, 'action=unblock');
                                    echo xtc_draw_hidden_field('block_id', (int)$r['block_id']);
                                    echo xtc_draw_hidden_field('scroll_to', 'bx_auto_blocks');
                                    ?>
                                        <button class="secondary" type="submit"><?php echo BX_SECURITY_MONITOR_UNBLOCK; ?></button>
                                    </form>
    
                                    <?php
                                    echo xtc_draw_form('block_to_whitelist_form_' . $form_id, FILENAME_BX_SECURITY_MONITOR, 'action=block_to_whitelist', 'post', 'onsubmit="return confirm(\'' . BX_SECURITY_MONITOR_CONFIRM_BLOCK_TO_WHITELIST . '\');"');
                                    echo xtc_draw_hidden_field('block_id', (int)$r['block_id']);
                                    echo xtc_draw_hidden_field('ip_address', msec_admin_h($r['ip_address']));
                                    echo xtc_draw_hidden_field('scroll_to', 'bx_auto_blocks');
                                    ?>
                                                                                <button type="submit"><?php echo BX_SECURITY_MONITOR_WHITELIST; ?></button>
                                      </form>
                                  </td>
                              </tr>
                          <?php
                            $form_id++;
                          }
                          ?>
                          </tbody>
                      </table>
                  </div>
              </div>

              <div class="msec-grid">
                  <div class="msec-box main">
                      <div class="msec-box-title pastel-lavender scroll-target" id="bx_permanent_whitelist"><?php echo BX_SECURITY_MONITOR_PERMANENT_WHITELIST; ?></div>
                      <div class="msec-box-body">
                        <?php
                        echo xtc_draw_form('add_whitelist_form', FILENAME_BX_SECURITY_MONITOR, 'action=add_whitelist');
                        echo xtc_draw_hidden_field('scroll_to', 'bx_permanent_whitelist');
                        ?>
                            <div class="msec-form-row">
                                <div>
                                    <label for="ip_address"><?php echo BX_SECURITY_MONITOR_IP_ADDRESS; ?></label>
                                    <?php echo xtc_draw_input_field('ip_address', '', 'id="ip_address"', true); ?>
                                </div>
                                <div>
                                    <label for="note"><?php echo BX_SECURITY_MONITOR_NOTE; ?></label>
                                    <?php echo xtc_draw_input_field('note', '', 'id="note"'); ?><br>
                                </div>
                                <div>
                                    <button class="msec-button" type="submit" style="margin-top: 19px;"><?php echo BX_SECURITY_MONITOR_ADD; ?></button>
                                </div>
                            </div>
                          </form>
                          <br>
                          <?php
                          echo xtc_draw_form('whitelist_current_form', FILENAME_BX_SECURITY_MONITOR, 'action=whitelist_current');
                          echo xtc_draw_hidden_field('scroll_to', 'bx_permanent_whitelist');
                          ?>
                                                        <button class="msec-button secondary" type="submit"><?php echo BX_SECURITY_MONITOR_ALLOW_CURRENT_ADMIN_IP; ?></button>
                          </form>
                          <br>
                          <table class="msec-table">
                              <thead>
                                  <tr>
                                      <th><?php echo BX_SECURITY_MONITOR_TH_IP; ?></th>
                                      <th><?php echo BX_SECURITY_MONITOR_NOTE; ?></th>
                                      <th><?php echo BX_SECURITY_MONITOR_TH_CREATED; ?></th>
                                      <th></th>
                                  </tr>
                              </thead>
                              <tbody>
                              <?php 
                              $wq = xtc_db_query("SELECT * FROM msec_whitelist ORDER BY date_added DESC");
                              if(xtc_db_num_rows($wq)<1) {
                                  echo '<tr><td colspan="4">' . BX_SECURITY_MONITOR_NO_ENTRIES . '</td></tr>';
                              }
                              $form_id = 0;
                              while($r = xtc_db_fetch_array($wq)){ ?>
                                  <tr>
                                      <td><?php echo msec_admin_h($r['ip_address']); ?></td>
                                      <td><?php echo msec_admin_h($r['note']); ?></td>
                                      <td><?php echo msec_admin_h($r['date_added']); ?></td>
                                      <td>
                                        <?php
                                                                                echo xtc_draw_form('delete_whitelist_form_'.$form_id, FILENAME_BX_SECURITY_MONITOR, 'action=delete_whitelist','post', 'onsubmit="return confirm(\'' . BX_SECURITY_MONITOR_CONFIRM_DELETE_WHITELIST_ENTRY . '\');"');
                                        echo xtc_draw_hidden_field('whitelist_id', (int)$r['whitelist_id']);
                                        echo xtc_draw_hidden_field('scroll_to', 'bx_permanent_whitelist');
                                        ?>
                                                                                <button class="msec-button" type="submit"><?php echo BX_SECURITY_MONITOR_DELETE; ?></button>
                                        </form>
                                      </td>
                                  </tr>
                              <?php $form_id++; } ?>
                              </tbody>
                          </table>
                      </div>
                  </div>

                  <div class="msec-box main">
                      <div class="msec-box-title pastel-rose"><?php echo BX_SECURITY_MONITOR_TEMP_ADMIN_APPROVALS; ?></div>
                      <div class="msec-box-body">
                          <div class="msec-info"><?php echo BX_SECURITY_MONITOR_TEMP_ADMIN_APPROVALS_INFO; ?></div>
                          <table class="msec-table">
                              <thead>
                                  <tr>
                                      <th><?php echo BX_SECURITY_MONITOR_TH_IP; ?></th>
                                      <th><?php echo BX_SECURITY_MONITOR_TH_ADMIN_ID; ?></th>
                                      <th><?php echo BX_SECURITY_MONITOR_TH_LAST_SEEN; ?></th>
                                      <th><?php echo BX_SECURITY_MONITOR_TH_EXPIRES_AT; ?></th>
                                  </tr>
                              </thead>
                              <tbody>
                              <?php
                              $tq = xtc_db_query("SELECT * FROM msec_admin_sessions WHERE expires_at > NOW() ORDER BY last_seen DESC LIMIT 100");
                              if(xtc_db_num_rows($tq)<1) {
                                  echo '<tr><td colspan="4">' . BX_SECURITY_MONITOR_NO_ACTIVE_ADMIN_APPROVALS . '</td></tr>';
                              }
                              while($r=xtc_db_fetch_array($tq)){ ?>
                                  <tr>
                                      <td><?php echo msec_admin_h($r['ip_address']); ?></td>
                                      <td><?php echo (int)$r['admin_customers_id']; ?></td>
                                      <td><?php echo msec_admin_h($r['last_seen']); ?></td>
                                      <td><?php echo msec_admin_h($r['expires_at']); ?></td>
                                  </tr>
                              <?php } ?>
                              </tbody>
                          </table>
                      </div>
                  </div>
              </div>

              <div class="msec-box main">
                  <div class="msec-box-title pastel-lemon scroll-target" id="bx_events"><?php echo BX_SECURITY_MONITOR_LATEST_SECURITY_EVENTS; ?></div>
                  <div class="msec-box-body">
                      <div class="msec-actions" style="justify-content:flex-end">
                        <?php
                        echo xtc_draw_form('clear_events_form', FILENAME_BX_SECURITY_MONITOR, 'action=clear_events','post', 'onsubmit="return confirm(\'' . BX_SECURITY_MONITOR_CONFIRM_CLEAR_EVENTS . '\');"' );
                        echo xtc_draw_hidden_field('scroll_to', 'bx_events');
                        ?>
                            <button class="light" type="submit" style="margin-bottom: 10px;"><?php echo BX_SECURITY_MONITOR_CLEAR_EVENTS_LOG; ?></button>
                        </form>
                      </div>
                      <table class="msec-table">
                          <thead>
                              <tr>
                                  <th><?php echo BX_SECURITY_MONITOR_TH_TIME; ?></th>
                                  <th><?php echo BX_SECURITY_MONITOR_TH_IP; ?></th>
                                  <th><?php echo BX_SECURITY_MONITOR_TH_URL; ?></th>
                                  <th><?php echo BX_SECURITY_MONITOR_TH_CATEGORY; ?></th>
                                  <th><?php echo BX_SECURITY_MONITOR_TH_REASON; ?></th>
                                  <th><?php echo BX_SECURITY_MONITOR_TH_SCORE; ?></th>
                                  <th><?php echo BX_SECURITY_MONITOR_TH_BLOCKED; ?></th>
                                  <th><?php echo BX_SECURITY_MONITOR_TH_USER_AGENT; ?></th>
                              </tr>
                          </thead>
                          <tbody>
                          <?php
                          $eq = xtc_db_query("SELECT * FROM msec_events ORDER BY date_added DESC LIMIT 250");
                          if(xtc_db_num_rows($eq) < 1) {
                              echo '<tr><td colspan="8">' . BX_SECURITY_MONITOR_NO_EVENTS_YET . '</td></tr>';
                          }
                          while($r = xtc_db_fetch_array($eq)){ ?>
                              <tr>
                                  <td><?php echo msec_admin_h($r['date_added']); ?></td>
                                  <td><?php echo msec_admin_h($r['ip_address']); ?></td>
                                  <td class="msec-path" title="<?php echo msec_admin_h($r['request_uri']); ?>"><?php echo msec_admin_h(msec_admin_short($r['request_uri'],90)); ?></td>
                                  <td><?php echo msec_admin_h($r['category']); ?></td>
                                  <td><?php echo msec_admin_h(msec_admin_short($r['reason'],80)); ?></td>
                                  <td><?php echo (int)$r['score']; ?></td>
                                  <td><?php echo (int)$r['is_blocked']===1?BX_SECURITY_MONITOR_YES:BX_SECURITY_MONITOR_NO; ?></td>
                                  <td><?php echo msec_admin_h(msec_admin_short($r['user_agent'],80)); ?></td>
                              </tr>
                          <?php } ?>
                          </tbody>
                      </table>
                  </div>
              </div>
            </div> <!-- boxCenter //-->

          </td>
        </tr>
      </table>
    </td>
  </tr>
</table>
<!-- body_eof //-->
<!-- footer //-->
<?php require(DIR_WS_INCLUDES.'footer.php'); ?>
<!-- footer_eof //-->
<script>
    jQuery(function ($) {
        // Ziel-ID, zu der nach dem Reload gescrollt werden soll.
        var hashId = '';

        // Bevorzugt den Query-Parameter ?scroll_to=..., damit kein nativer Hash-Sprung passiert.
        var queryMatch = location.search.match(/[?&]scroll_to=([^&]+)/);

        if (queryMatch && queryMatch[1]) {
            try {
                // + in Query-Strings steht für Leerzeichen.
                hashId = decodeURIComponent(queryMatch[1].replace(/\+/g, ' '));
            } catch (e) {
                // Fallback: bei fehlerhafter URL-Kodierung den Rohwert verwenden.
                hashId = queryMatch[1];
            }
        }

        if (!hashId && location.hash) {
            // Fallback auf klassischen Hash (#anker), falls kein Query-Parameter vorhanden ist.
            var rawHash = location.hash.slice(1);
            try {
                hashId = decodeURIComponent(rawHash);
            } catch (e) {
                hashId = rawHash;
            }
        }

        // Nur sichere Zeichen für DOM-ID-Auswahl erlauben.
        hashId = hashId.replace(/[^a-zA-Z0-9_-]/g, '');
        if (!hashId) {
            return;
        }

        // Clientseitige Whitelist: nur bekannte Bereiche duerfen als Scrollziel dienen.
        var permittedAnchorExact = [
            'bx_settings',
            'bx_manual_rules',
            'bx_auto_blocks',
            'bx_permanent_whitelist',
            'bx_events'
        ];

        if ($.inArray(hashId, permittedAnchorExact) === -1) {
            return;
        }

        // Ziel-Element im DOM suchen.
        var $ziel = $('#' + hashId);
        if ($ziel.length < 1) {
            return;
        }

        // Entfernt scroll_to nach dem Scrollen wieder aus der URL.
        function removeScrollToParam(search) {
            var cleaned = search.replace(/([?&])scroll_to=[^&]*(&)?/, function (match, lead, tail) {
                if (lead === '?' && tail) {
                    return '?';
                }
                return lead === '?' ? '' : (tail ? '&' : '');
            });

            cleaned = cleaned.replace(/\?&/, '?').replace(/&&/, '&');
            if (cleaned === '?') {
                cleaned = '';
            }
            if (cleaned.charAt(0) === '&') {
                cleaned = '?' + cleaned.slice(1);
            }

            return cleaned;
        }

        // Kurze Verzögerung: erst scrollen, wenn Layout und Tabellenhöhen stabil sind.
        window.setTimeout(function () {
            // jQuery animate berücksichtigt scroll-margin-top nicht automatisch.
            // Daher lesen wir den CSS-Wert aus und rechnen ihn als Offset ab.
            var scrollMarginTop = parseInt($ziel.css('scroll-margin-top'), 10);
            if (isNaN(scrollMarginTop)) {
                scrollMarginTop = 0;
            }

            // Zielposition inkl. Offset berechnen (nicht kleiner als 0).
            var targetTop = Math.max(0, $ziel.offset().top - scrollMarginTop);

            // Weicher Scroll von aktueller Position zur Zielposition.
            $('html, body').stop(true).animate(
                { scrollTop: targetTop },
                800,
                'swing',
                function () {
                    // Nach erfolgreichem Scrollen URL ohne scroll_to aktualisieren.
                    if (window.history && typeof window.history.replaceState === 'function') {
                        var cleanSearch = removeScrollToParam(location.search);
                        window.history.replaceState(null, '', location.pathname + cleanSearch);
                    }
                }
            );
        }, 500);
    });
</script>
</body>
</html>
<?php require(DIR_WS_INCLUDES.'application_bottom.php'); ?>