<?php

require_once 'config.php';

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
        return $stmt->fetch(PDO::FETCH_ASSOC) !== false;
    }

    public function getUserCredentialId($username)
    {
        $stmt = $this->db->prepare("SELECT credential_id FROM users WHERE username = :username");
        $stmt->bindParam(':username', $username);
        $stmt->execute();
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($result) {
            return $result['credential_id'];
        } else {
            throw new Exception("User not found or credential ID not set.");
        }
    }
}
