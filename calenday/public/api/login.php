<?php
require_once '../../config.php';
require_once '../../src/Auth.php';
require_once '../../vendor/autoload.php';

use Webauthn\PublicKeyCredentialRequestOptions;

header('Content-Type: application/json');

$auth = new Auth();
$username = $_POST['username'];

// Step 1: Start login
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['username'])) {
    $credentialId = $auth->getUserCredentialId($username);
    $publicKeyOptions = new PublicKeyCredentialRequestOptions($credentialId, [
        // Authenticators options
    ]);

    echo json_encode($publicKeyOptions);
    exit;
}

// Step 2: Finish login
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['assertion'])) {
    $assertion = $_POST['assertion'];
    // Validate assertion with the stored credential
    if ($auth->login($username, $assertion['id'])) {
        echo json_encode(['status' => 'ok']);
    } else {
        http_response_code(401);
        echo json_encode(['status' => 'failed']);
    }
    exit;
}
