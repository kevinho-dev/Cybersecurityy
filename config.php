<?php
/**
 * config.php — Central configuration & security
 */

// Session hardening
ini_set('session.cookie_httponly', 1);           // XSS: JS can't access cookie
ini_set('session.cookie_samesite', 'Lax');       // CSRF: no cross-site cookies
if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    ini_set('session.cookie_secure', 1);         // HTTPS only
}

session_start();

// Session hijacking protection: verify User-Agent
if (isset($_SESSION['user_agent'])) {
    if ($_SESSION['user_agent'] !== $_SERVER['HTTP_USER_AGENT']) {
        session_unset();
        session_destroy();
        session_start();
        header("Location: login.php");
        exit;
    }
} else {
    $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
}

// Database: PDO + Prepared Statements (SQL injection prevention)
try {
    $conn = new PDO("mysql:host=localhost;dbname=cybersecurity", "root", "");
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    // Never expose DB errors to users (info leakage)
    die("Database error. Try again later.");
}
?>