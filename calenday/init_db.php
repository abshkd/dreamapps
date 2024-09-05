<?php
require 'config.php';

$db = getDbConnection();

$db->exec("CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    credential_id TEXT UNIQUE,
    public_key TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)");

$db->exec("CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    title TEXT,
    description TEXT,
    start_time DATETIME,
    end_time DATETIME,
    location TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
)");

$db->exec("CREATE TABLE IF NOT EXISTS bookings (
    id INTEGER PRIMARY KEY,
    event_id INTEGER,
    user_id INTEGER,
    status TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(event_id) REFERENCES events(id),
    FOREIGN KEY(user_id) REFERENCES users(id)
)");

echo "Database initialized successfully.";
