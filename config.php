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
?>