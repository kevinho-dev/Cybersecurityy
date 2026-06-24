<?php
require_once 'config.php';

// This endpoint is called via JavaScript fetch() — it always responds with JSON.
header('Content-Type: application/json');

/**
 * Sends a JSON error response and stops the script.
 * We use this helper to avoid repeating the same json_encode + exit pattern.
 */
function jsonError(string $message): never
{
    echo json_encode(['success' => false, 'error' => $message]);
    exit;
}

// All checks below return JSON, keeping the response shape consistent for JavaScript.

// Only logged-in users may verify passwords.
if (!isset($_SESSION['user_id'])) jsonError('Not authenticated.');

// Verify the CSRF token to block forged requests.
if (!verifyCsrf()) jsonError('Invalid request.');

$token    = $_POST['token']    ?? '';
$password = $_POST['password'] ?? '';
$ip       = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

if (!$token || !$password) jsonError('Missing data.');

// Reject tokens that don't match our 64-character hex format before querying the database.
// This prevents malformed input from reaching the SQL query.
if (!preg_match('/^[a-f0-9]{64}$/', $token)) jsonError('File not found.');

// Rate-limit unlock attempts to prevent password brute-forcing (10 attempts per 10 minutes).
if (isRateLimited($conn, 'unlock_failed', $ip, 10, 10)) {
    jsonError('Too many attempts. Try again later.');
}

// Look up the file's stored password hash.
$stmt = $conn->prepare("SELECT password FROM uploads WHERE share_token = ?");
$stmt->execute([$token]);
$file = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$file) jsonError('File not found.');

if (password_verify($password, $file['password'])) {
    // Mark this token as unlocked in the session so download.php can serve
    // the file without asking for the password again on the same visit.
    $_SESSION['unlocked_tokens'][$token] = true;
    echo json_encode(['success' => true]);
} else {
    // Log the failed attempt so we can spot brute-force attacks in the activity log.
    logEvent($conn, 'unlock_failed', $_SESSION['user_id'], null, null, "Wrong password for token $token");
    jsonError('Wrong password.');
}
