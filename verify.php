<?php
/**
 * verify.php — password verification endpoint
 * Called via fetch() from dashboard.js / download.js.
 * Always returns JSON: {success: true} or {success: false, error: "..."}
 */
require_once 'config.php';

header('Content-Type: application/json');

$token    = $_POST['token']    ?? '';
$password = $_POST['password'] ?? '';
$action   = $_POST['action']   ?? ''; // 'download' or 'share'

// Bail early if required fields are missing
if (empty($token) || empty($password)) {
    echo json_encode(['success' => false, 'error' => 'Missing data.']);
    exit;
}

// Look up the file's stored (hashed) password by its share token
$stmt = $conn->prepare("SELECT password FROM uploads WHERE share_token = ?");
$stmt->execute([$token]);
$file = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$file) {
    echo json_encode(['success' => false, 'error' => 'File not found.']);
    exit;
}

// password_verify compares plaintext against the bcrypt hash (timing-safe)
if (password_verify($password, $file['password'])) {
    // Mark this token as unlocked for the current browser session
    $_SESSION['unlocked_tokens'][$token] = true;
    echo json_encode(['success' => true]);
} else {
    echo json_encode(['success' => false, 'error' => 'Wrong password.']);
}