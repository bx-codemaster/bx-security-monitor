<?php
/* Security Monitor Bootstrap - wird vor Session und Tracking geladen. */
if (defined('MODULE_BX_SECURITY_MONITOR_STATUS') && MODULE_BX_SECURITY_MONITOR_STATUS === 'True') {
    $guard       = DIR_FS_CATALOG . 'includes/modules/bx_guard.php';
    $login_guard = DIR_FS_CATALOG . 'includes/modules/bx_admin_login_guard.php';

    if (is_file($guard)) {
        require_once($guard);
    }
    if (is_file($login_guard)) {
        require_once($login_guard);
    }
}
?>
