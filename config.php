<?php
// Stap 2 Encryptie: .htaccess (HTTPS), password_hash (Bcrypt), SHA-256 (Bestanden).

// Sessie beveiligingsinstellingen (Session Hardening)
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_samesite', 'Lax');

// Dwing secure cookies af als HTTPS actief is
if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    ini_set('session.cookie_secure', 1);
}

session_start();

// Bescherming tegen Session Hijacking (User-Agent controle)
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

// Veilige database verbinding via PDO (SQL-injection preventie)
try {
    $conn = new PDO("mysql:host=localhost;dbname=cybersecurity", "root", "");
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    // Toon een generieke foutmelding om informatie-lekkage te voorkomen
    die("Er is een databasefout opgetreden. Probeer het later opnieuw.");
}