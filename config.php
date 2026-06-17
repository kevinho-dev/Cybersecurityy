<?php
/**
 * 1. VEILIGE SESSIE-INSTELLINGEN (SESSION HARDENING)
 * Deze instellingen moeten ALTIJD worden gedefinieerd VOORDAT session_start() wordt aangeroepen.
 */

// Zorgt ervoor dat JavaScript de session-cookie niet kan uitlezen. 
// Dit biedt cruciale bescherming tegen Cross-Site Scripting (XSS) aanvallen.
ini_set('session.cookie_httponly', 1);

// Beperkt het meesturen van cookies bij cross-site verzoeken.
// 'Lax' helpt effectief bij het blokkeren van Cross-Site Request Forgery (CSRF) aanvallen.
ini_set('session.cookie_samesite', 'Lax');

// Controleer of de verbinding via HTTPS loopt. Als dat zo is, dwingen we af dat de 
// session-cookie alleen over een versleutelde verbinding mag worden verzonden.
if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    ini_set('session.cookie_secure', 1);
}

// Start of hervat de huidige sessie op basis van de session identifier (cookie).
session_start();


/**
 * 2. PREVENTIE VAN SESSIE-OVERNAMES (SESSION HIJACKING)
 * We binden de sessie aan de specifieke browser/user-agent van de gebruiker.
 */
if (isset($_SESSION['user_agent'])) {
    // Als de User-Agent tijdens de sessie plotseling verandert, is er mogelijk sprake van session hijacking.
    if ($_SESSION['user_agent'] !== $_SERVER['HTTP_USER_AGENT']) {
        // Vernietig de verdachte sessie onmiddellijk om misbruik te stoppen.
        session_unset();
        session_destroy();
        session_start();
        header("Location: login.php");
        exit;
    }
} else {
    // Sla de unieke browser-identiteit op bij de allereerste pagina-aanroep binnen de sessie.
    $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];
}


/**
 * 3. GECENTRALISEERDE PDO DATABASE VERBINDING
 * We gebruiken PDO met Prepared Statements om SQL-injecties onmogelijk te maken.
 */
try {
    // Maak verbinding met de MySQL database
    $conn = new PDO("mysql:host=localhost;dbname=cybersecurity", "root", "");
    // Zorg ervoor dat PDO bij fouten een Exception gooit, zodat we deze netjes kunnen opvangen.
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    // Beveiligingstip: Log de echte foutmelding intern op de server, maar toon deze NOOIT aan de client.
    // Het tonen van rauwe SQL-fouten kan database-structuren of inloggegevens lekken naar kwaadwillenden.
    error_log($e->getMessage()); 
    die("Er is een databasefout opgetreden. Probeer het later opnieuw.");
}