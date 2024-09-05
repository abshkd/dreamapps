<?php
require_once 'config.php';

use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialSourceRepository;

class Auth
{
    private $db;

    public function __construct()
    {
        $this->db = getDbConnection();
    }

    public function register($username, $credentialId, $publicKey)
    {
        $stmt = $this->db->prepare("INSERT INTO users (username, credential_id, public_key) VALUES (:username, :credential_id, :public_key)");
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':credential_id', $credentialId);
        $stmt->bindParam(':public_key', $publicKey);
        $stmt->execute();
    }

    public function login($username, $credentialId)
    {
        $stmt = $this->db->prepare("SELECT * FROM users WHERE username = :username AND credential_id = :credential_id");
        $stmt->bindParam(':username', $username);
        $stmt->bindParam(':credential_id', $credentialId);
        $stmt->execute();
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }
}
