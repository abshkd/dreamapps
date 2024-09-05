<?php
require_once 'vendor/autoload.php'; // Composer autoload for WebAuthn
require_once 'config.php';
require_once 'src/Auth.php';

use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\AttestationConveyancePreference;
use Base64Url\Base64Url;

header('Content-Type: application/json'); // Ensure correct Content-Type header is set

$auth = new Auth(); // Initialize the Auth class

$action = $_GET['action'] ?? null;  // 'register' or 'login'
$step = $_GET['step'] ?? null;      // 'start' or 'finish'

// Validate input parameters
if (!$action || !$step) {
    http_response_code(400);
    echo json_encode(['error' => 'Invalid request. Action and step parameters are required.']);
    exit;
}

$data = json_decode(file_get_contents('php://input'), true);
$username = $data['username'] ?? '';

if (!$username) {
    http_response_code(400);
    echo json_encode(['error' => 'Username is required.']);
    exit;
}

try {
    if ($action === 'register' && $step === 'start') {
        // Register Start: Create PublicKeyCredentialCreationOptions
        $rpEntity = new PublicKeyCredentialRpEntity(
            'calendar.airith.com',  // Your domain name
            'Self-Hosted Calendar App'
        );

        $userId = random_bytes(16);  // Generate a unique, random user ID

        $userEntity = new PublicKeyCredentialUserEntity(
            $username,
            Base64Url::encode($userId),  // Base64 URL-encoded user ID
            $username
        );

        $challenge = random_bytes(32);  // Generate a secure random challenge
        $challengeBase64Url = Base64Url::encode($challenge);  // Convert to Base64 URL encoding

        $pubKeyCredParams = [
            new PublicKeyCredentialParameters('public-key', -7),  // ES256 algorithm
            new PublicKeyCredentialParameters('public-key', -257)  // RS256 algorithm
        ];

        $authenticatorSelection = new AuthenticatorSelectionCriteria(
            false,  // requireResidentKey
            'preferred'  // userVerification
        );

        $creationOptions = new PublicKeyCredentialCreationOptions(
            $rpEntity,
            $userEntity,
            $challengeBase64Url,
            $pubKeyCredParams,
            [],  // excludeCredentials
            60000,  // Timeout in milliseconds
            $authenticatorSelection,
            AttestationConveyancePreference::NONE
        );

        echo json_encode($creationOptions);
        exit;
    } elseif ($action === 'register' && $step === 'finish') {
        // Register Finish: Validate and store credential
        $credential = $data['credential'] ?? null;
        if (!$credential) {
            http_response_code(400);
            echo json_encode(['error' => 'Credential is required.']);
            exit;
        }

        $auth->register($username, $credential['id'], $credential['publicKey']);
        echo json_encode(['status' => 'ok']);
        exit;
    } elseif ($action === 'login' && $step === 'start') {
        // Login Start: Create PublicKeyCredentialRequestOptions
        $credentialId = $auth->getUserCredentialId($username);

        if (!$credentialId) {
            http_response_code(404);
            echo json_encode(['error' => 'User not found or credential ID not available.']);
            exit;
        }

        $challenge = random_bytes(32);  // Generate a secure random challenge
        $challengeBase64Url = Base64Url::encode($challenge);  // Convert to Base64 URL encoding

        $allowCredentials = [
            new PublicKeyCredentialDescriptor('public-key', [Base64Url::decode($credentialId)])
        ];

        $requestOptions = new PublicKeyCredentialRequestOptions(
            $challengeBase64Url,
            60000,  // Timeout in milliseconds
            'calendar.airith.com',  // Your domain name
            $allowCredentials,
            'preferred'  // userVerification
        );

        echo json_encode($requestOptions);
        exit;
    } elseif ($action === 'login' && $step === 'finish') {
        // Login Finish: Validate assertion with the stored credential
        $assertion = $data['assertion'] ?? null;
        if (!$assertion) {
            http_response_code(400);
            echo json_encode(['error' => 'Assertion is required.']);
            exit;
        }

        if ($auth->login($username, $assertion['id'])) {
            echo json_encode(['status' => 'ok']);
        } else {
            http_response_code(401);
            echo json_encode(['error' => 'Invalid credentials.']);
        }
        exit;
    } else {
        http_response_code(400);
        echo json_encode(['error' => 'Invalid action or step.']);
        exit;
    }
} catch (Exception $e) {
    error_log("Error during $action $step: " . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'An internal error occurred.']);
}
