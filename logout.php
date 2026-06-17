<?php
/**
 * logout.php — Secure session destruction (3 steps)
 */
require_once 'config.php';

// Step 1: Clear runtime session array
$_SESSION = [];

// Step 2: Delete session cookie from browser
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(
        session_name(),
        '',
        time() - 42000,  // Past date: browser deletes cookie
        $params["path"],
        $params["domain"],
        $params["secure"],
        $params["httponly"]
    );
}

// Step 3: Destroy session on server (session_id becomes invalid)
session_destroy();

header("Location: login.php");
exit;
?>