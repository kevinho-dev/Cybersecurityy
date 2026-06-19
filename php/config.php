<?php
/**
 * config.php — runs first on every page (via require_once)
 * Sets up sessions securely and opens the database connection.
 */

// httponly: JS can't steal the cookie (blocks XSS attacks)
ini_set('session.cookie_httponly', 1);
// Lax: cookie isn't sent on cross-site requests (reduces CSRF risk)
ini_set('session.cookie_samesite', 'Lax');
// secure: only send cookie over HTTPS
if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    ini_set('session.cookie_secure', 1);
}

session_start();

// If the User-Agent changes mid-session, it might be a stolen cookie — kill it
if (isset($_SESSION['user_agent'])) {
    if ($_SESSION['user_agent'] !== $_SERVER['HTTP_USER_AGENT']) {
        session_unset();
        session_destroy();
        session_start();
        header("Location: ../index.php");
        exit;
    }
} else {
    $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
}

// PDO with prepared statements prevents SQL injection
try {
    $conn = new PDO("mysql:host=localhost;dbname=cybersecurity", "root", "");
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    // Never expose the real error — it could leak table names, credentials, etc.
    die("Database error. Try again later.");
}

// Make sure the logs table exists (auto-create so no manual migration is needed)
$conn->exec("
    CREATE TABLE IF NOT EXISTS logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        event_type VARCHAR(30) NOT NULL,
        username VARCHAR(255) NULL,
        user_id INT NULL,
        file_name VARCHAR(255) NULL,
        ip_address VARCHAR(45) NULL,
        details VARCHAR(255) NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
");

// Make sure the users table has a 'role' column (admin / user).
// Wrapped in try/catch because MySQL has no "ADD COLUMN IF NOT EXISTS" before 8.0.29,
// so on every page load we just try to add it and silently ignore the
// "duplicate column" error if it's already there.
try {
    $conn->exec("ALTER TABLE users ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'user'");
} catch (PDOException $e) {
    // Column already exists — nothing to do
}

require_once __DIR__ . '/logger.php';
?>