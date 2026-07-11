<?php
  /* --------------------------------------------------------------
   $Id: login_admin.php 10360 2016-11-02 11:04:11Z GTB $

   modified eCommerce Shopsoftware
   http://www.modified-shop.org

   Copyright (c) 2009 - 2013 [www.modified-shop.org]
   Released under the GNU General Public License
   --------------------------------------------------------------*/
   
@ini_set('display_errors', false);
error_reporting(0);

define('_MODIFIED_SHOP_LOGIN',1);

// Base/PHP_SELF/SSL-PROXY
require_once ('inc/set_php_self.inc.php');
$PHP_SELF = set_php_self();

// Für den Reparatur-Loginpfad den Security-Guard gezielt vorladen,
// damit fehlgeschlagene Admin-Logins auch hier erfasst werden.
if ( $_SERVER['REQUEST_METHOD'] === 'POST' && (isset($_POST['repair']) || isset($_POST['show_error'])) ) {
    try {
      $GLOBALS['msec_login_admin_failed'] = false;

      if (file_exists('includes/local/configure.php')) {
        require_once('includes/local/configure.php');
      } elseif (file_exists('includes/configure.php')) {
        require_once('includes/configure.php');
      }

      if (defined('DIR_WS_INCLUDES')
          && defined('DIR_FS_INC')
          && defined('DB_MYSQL_TYPE')
          && defined('DIR_FS_CATALOG')
          && is_file(DIR_WS_INCLUDES.'database_tables.php')
          && is_file(DIR_FS_INC.'db_functions_'.DB_MYSQL_TYPE.'.inc.php')
          && is_file(DIR_FS_INC.'db_functions.inc.php')) {
        require_once(DIR_WS_INCLUDES.'database_tables.php');
        require_once(DIR_FS_INC.'db_functions_'.DB_MYSQL_TYPE.'.inc.php');
        require_once(DIR_FS_INC.'db_functions.inc.php');

        if (function_exists('xtc_db_connect')) {
          xtc_db_connect();
          $configuration_table = defined('TABLE_CONFIGURATION') ? TABLE_CONFIGURATION : 'configuration';
          $configuration_query = xtc_db_query("SELECT configuration_key, configuration_value FROM ".$configuration_table);
          while ($configuration = xtc_db_fetch_array($configuration_query)) {
            defined($configuration['configuration_key']) OR define($configuration['configuration_key'], stripslashes($configuration['configuration_value']));
          }

          $login_guard = DIR_FS_CATALOG.'includes/modules/bx_admin_login_guard.php';
          if (is_file($login_guard)) {
            require_once($login_guard);
          }
        }
      }
    } catch (\Throwable $e) {
        // bewusst verschlucken - ein Fehler im Security-Guard
        // darf den Admin-Login nicht lahmlegen
    }
}

if (isset($_GET['repair']) || isset($_POST['repair']) || isset($_GET['show_error']) || isset($_POST['show_error'])) {
  include('includes/login_admin.php');
} else {
  include('includes/login_shop.php');
}
