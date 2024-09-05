<?php
// To remove expired files
$uploadDir = 'uploads/';
foreach (glob("$uploadDir*.expire") as $expireFile) {
    $expirationTime = file_get_contents($expireFile);
    if (time() > $expirationTime) {
        $originalFile = str_replace('.expire', '', $expireFile);
        if (file_exists($originalFile)) {
            unlink($originalFile); // Delete the original file
        }
        unlink($expireFile); // Delete the expiration file
    }
}
