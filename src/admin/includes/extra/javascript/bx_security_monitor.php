<?php
  defined('_VALID_XTC') or die('Direct Access to this location is not allowed.');

  if (defined('MODULE_BX_SECURITY_MONITOR_STATUS') && 'True' == MODULE_BX_SECURITY_MONITOR_STATUS && basename($_SERVER['PHP_SELF']) == 'bx_security_monitor.php') {
?>
<script>
"use strict";
document.addEventListener('DOMContentLoaded', function () {
  var $stack = $(".fixed_messageStack");
  if ($stack.length && !$stack.data("bxSecurityMonitorInit")) {
    $stack.data("bxSecurityMonitorInit", true).slideDown("slow", function() {
      setTimeout(function() { $stack.slideUp("slow"); }, 2000);
    });
  }
});
</script>
<?php
 }
?>