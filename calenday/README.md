# Self-Hosted Calendar App - Calenday

A self-hosted, Calendly-like calendar application built with PHP, SQLite, and passkey-based authentication (WebAuthn). This app allows users to register, log in, manage events, and book appointments securely without traditional passwords.

## Features

- Passkey-based authentication using WebAuthn.
- Event management (create, edit, delete).
- Appointment booking.
- Lightweight and easy to deploy.
- Secure with no need for traditional passwords.

## Requirements

- PHP >= 7.4
- Composer
- SQLite (pre-installed with PHP)
- HTTPS-enabled server (e.g., DreamHost)

## Installation

Follow these steps to set up the project locally or on a server.

### 1. Clone the Repository

You ned to ensure paths match whatever setup is in your webhost.
```bash
git clone ...
cd calenday
composer install
DB_PATH=./data/database.sqlite
php init_db.php
```
### 2. Access the Application
Register and Login

### 3. Profit (or not)