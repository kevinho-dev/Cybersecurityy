<?php
/**
 * logout.php — destroys the session completely (3 steps required)
 */
require_once 'config.php';

// Step 1: Wipe all session variables from memory
$_SESSION = [];

// Step 2: Tell the browser to delete the session cookie
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(
        session_name(),
        '',
        time() - 42000, // Expiry in the past → browser deletes it immediately
        $params["path"],
        $params["domain"],
        $params["secure"],
        $params["httponly"]
    );
}

// Step 3: Delete the session data on the server
session_destroy();

header("Location: ../php/login.php");
exit;
?>