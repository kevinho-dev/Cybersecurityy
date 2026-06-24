<?php
require_once 'config.php';

// Only logged-in users may load thumbnails.
if (!isset($_SESSION['user_id'])) {
    http_response_code(403);
    exit;
}

$token = $_GET['token'] ?? '';

if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
    http_response_code(400);
    exit;
}

// Fetch the file record — we allow the file owner OR a user who has unlocked
// the token this session to load the thumbnail.
$stmt = $conn->prepare(
    "SELECT stored_name, mime_type, password, user_id FROM uploads WHERE share_token = ?"
);
$stmt->execute([$token]);
$file = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$file || !in_array($file['mime_type'], get_image_mimes())) {
    http_response_code(404);
    exit;
}

// SECURITY: Only serve the thumbnail if:
//   (a) The requesting user is the file owner, OR
//   (b) The file has no password, OR
//   (c) The user has verified the password this session.
$isOwner   = ((int) $file['user_id'] === (int) $_SESSION['user_id']);
$noPass    = empty($file['password']);
$unlocked  = isset($_SESSION['unlocked_tokens'][$token]);

if (!$isOwner && !$noPass && !$unlocked) {
    http_response_code(403);
    exit;
}

$uploadsDir = realpath(__DIR__ . '/../uploads/');
$filePath   = realpath(__DIR__ . '/../uploads/' . $file['stored_name']);

if (
    !$filePath   ||
    !$uploadsDir ||
    !str_starts_with($filePath, $uploadsDir . DIRECTORY_SEPARATOR) ||
    !is_file($filePath)
) {
    http_response_code(404);
    exit;
}

header('Content-Type: '    . $file['mime_type']);
header('Cache-Control: private, max-age=3600');
readfile($filePath);