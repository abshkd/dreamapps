<?php
require_once 'config.php';

class Booking
{
    private $db;

    public function __construct()
    {
        $this->db = getDbConnection();
    }

    public function createBooking($eventId, $userId)
    {
        $stmt = $this->db->prepare("INSERT INTO bookings (event_id, user_id, status) VALUES (:event_id, :user_id, 'confirmed')");
        $stmt->bindParam(':event_id', $eventId);
        $stmt->bindParam(':user_id', $userId);
        $stmt->execute();
    }

    public function getBookings($userId)
    {
        $stmt = $this->db->prepare("SELECT * FROM bookings WHERE user_id = :user_id ORDER BY created_at DESC");
        $stmt->bindParam(':user_id', $userId);
        $stmt->execute();
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }
}
