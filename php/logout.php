<?php
require_once 'config.php';

// Logging out has three steps. All three are required for a complete logout.
// Missing any step can leave the user vulnerable to session hijacking.

// Step 1 — Erase session data from PHP's memory.
$_SESSION = [];

// Step 2 — Tell the browser to delete the session cookie immediately.
// We set its expiry time in the past (time() - 42000) so the browser removes it.
if (ini_get('session.use_cookies')) {
    $params = session_get_cookie_params();
    setcookie(
        session_name(), '',
        time() - 42000,
        $params['path'], $params['domain'],
        $params['secure'], $params['httponly']
    );
}

// Step 3 — Delete the session record from the server's storage.
session_destroy();

// Send the user back to the login page.
header('Location: login.php');
exit;
