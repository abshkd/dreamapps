<?php
require_once '../../config.php';
require_once '../../src/Auth.php';
require_once '../../vendor/autoload.php'; // Composer autoload for WebAuthn

use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

header('Content-Type: application/json');

$auth = new Auth();
$username = $_POST['username'];

// Step 1: Start registration
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['username'])) {
    $rpEntity = new PublicKeyCredentialRpEntity('self-hosted-calendar-app', 'Self-Hosted Calendar App');
    $userEntity = new PublicKeyCredentialUserEntity($username, random_bytes(16), $username);
    $publicKeyOptions = new PublicKeyCredentialCreationOptions($rpEntity, $userEntity, random_bytes(16), [
        // Authenticators options
    ]);

    echo json_encode($publicKeyOptions);
    exit;
}

// Step 2: Finish registration
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['credential'])) {
    // Validate and store credential
    $credential = $_POST['credential'];
    $auth->register($username, $credential['id'], $credential['publicKey']);
    echo json_encode(['status' => 'ok']);
    exit;
}
