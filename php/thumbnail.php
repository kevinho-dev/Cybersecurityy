<?php
/**
 * thumbnail.php — serves a small preview image for a file the logged-in
 * user owns. No download password needed here: being logged in as the
 * owner is already proof of identity, and this only ever runs on the
 * user's own dashboard.
 *
 * Usage: <img src="php/thumbnail.php?token=XXXX">
 */
require_once 'config.php';

if (!isset($_SESSION['user_id'])) {
    http_response_code(403);
    exit;
}

$token = $_GET['token'] ?? '';

if (!$token) {
    http_response_code(400);
    exit;
}

$stmt = $conn->prepare("SELECT stored_name, mime_type FROM uploads WHERE share_token = ? AND user_id = ?");
$stmt->execute([$token, $_SESSION['user_id']]);
$file = $stmt->fetch(PDO::FETCH_ASSOC);

// Only serve actual images — anything else (pdf, docx, etc.) gets a 404
// and the front-end falls back to a generic icon instead.
$imageMimes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];

if (!$file || !in_array($file['mime_type'], $imageMimes)) {
    http_response_code(404);
    exit;
}

$path = __DIR__ . '/../uploads/' . $file['stored_name'];

if (!is_file($path)) {
    http_response_code(404);
    exit;
}

header('Content-Type: ' . $file['mime_type']);
header('Cache-Control: private, max-age=3600');
readfile($path);