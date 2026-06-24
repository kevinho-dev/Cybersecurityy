<?php
require_once 'config.php';

// Only logged-in users may load thumbnails.
// Returning 403 Forbidden without any body prevents leaking file existence.
if (!isset($_SESSION['user_id'])) {
    http_response_code(403);
    exit;
}

$token = $_GET['token'] ?? '';

// Reject malformed tokens before touching the database.
if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
    http_response_code(400);
    exit;
}

// The WHERE clause includes user_id so a user can only load thumbnails for
// their own files — not for files uploaded by other users.
// This prevents one user from enumerating another user's files via this endpoint.
$stmt = $conn->prepare(
    "SELECT stored_name, mime_type FROM uploads WHERE share_token = ? AND user_id = ?"
);
$stmt->execute([$token, $_SESSION['user_id']]);
$file = $stmt->fetch(PDO::FETCH_ASSOC);

// Only serve the file if it exists AND is an image type.
if (!$file || !in_array($file['mime_type'], get_image_mimes())) {
    http_response_code(404);
    exit;
}

$uploadsDir = realpath(__DIR__ . '/../uploads/');
$filePath   = realpath(__DIR__ . '/../uploads/' . $file['stored_name']);

// PATH-TRAVERSAL GUARD — same logic as download.php.
// Verify the resolved path is inside the uploads folder before serving.
if (
    !$filePath   ||
    !$uploadsDir ||
    !str_starts_with($filePath, $uploadsDir . DIRECTORY_SEPARATOR) ||
    !is_file($filePath)
) {
    http_response_code(404);
    exit;
}

// Send the image with a short cache time so the browser doesn't reload it on every visit.
header('Content-Type: '    . $file['mime_type']);
header('Cache-Control: private, max-age=3600');
readfile($filePath);
