<?php 

/**
 * Windows Live Services has the redirect URL as this page and appropriate 
 * get and post parameters passed to Windows Live Handler by this file.
 *
 *
 * @version     $Id: windowslive.webauth-handler.php $
 * @copyright   Copyright (c) 2010 Schakra, Inc. All Rights Reserved.
 * @license     http://www.gnu.org/licenses/gpl-2.0.html
 * @package     Drupal
 * @subpackage  WindowsLiveID
 * @since       1.0
 */

    if ($_REQUEST['appctx'] == null) {
        printf("<p>".
               " Windows Live ID Authentication plugin configuration may not be correct.".
               " Please cross check the configuration values against Windows Live Web Application configuration.".
               "</p>");
        return;
    }
    else {    
        // Get the base path of Drupal installation.
        $drupal_uri = $_REQUEST['appctx']. '?q=windowslive/handler';
    }
?>

<html>
  <head>
    <title>Windows Live ID Authentication Handler</title>
  </head>
  <body onload="document.getElementById('responseform').submit();">
    <form name="responseform" id="responseform" method="POST" action="<?php echo $drupal_uri; ?>">
      <input type="hidden" name="action" value="<?php echo $_REQUEST['action']; ?>" />
      <input type="hidden" name="stoken" value="<?php echo $_REQUEST['stoken']; ?>" />
    </form>
  </body>
</html>
