<?php
// Laad de centrale configuratie om de huidige sessie context te verkrijgen
require_once 'config.php';

// Stap 1: Maak de runtime sessie-array volledig leeg
$_SESSION = [];

// Stap 2: Vernietig de sessie-cookie in de browser van de gebruiker
if (ini_get("session.use_cookies")) {
    // Haal de huidige cookie-instellingen (zoals pad en domein) op zodat we de juiste cookie raken
    $params = session_get_cookie_params();
    // Overschrijf de session-cookie en zet de verlooppediode ver in het verleden (time() - 42000)
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
}

// Stap 3: Vernietig de fysieke opslag van de sessiedata op de webserver zelf
session_destroy();

// Stap 4: Stuur de uitgelogde bezoeker terug naar het inlogscherm
header("Location: login.php");
exit;
?>