<?php
require_once 'config.php';

// This endpoint is called via JavaScript fetch() — always responds with JSON.
header('Content-Type: application/json');

function jsonError(string $message): never
{
    echo json_encode(['success' => false, 'error' => $message]);
    exit;
}

function jsonOk(string $message = 'OK'): never
{
    echo json_encode(['success' => true, 'message' => $message]);
    exit;
}

// Only logged-in users may share files.
if (!isset($_SESSION['user_id'])) jsonError('Not authenticated.');

// Verify CSRF token to block forged requests.
if (!verifyCsrf()) jsonError('Invalid request.');

$token    = $_POST['token']    ?? '';
$username = trim($_POST['share_with_username'] ?? '');

if (!$token || !$username) jsonError('Missing data.');

if (!preg_match('/^[a-f0-9]{64}$/', $token)) jsonError('Invalid token.');

// Look up the file — the sharer MUST own it.
$stmt = $conn->prepare("SELECT id, original_name FROM uploads WHERE share_token = ? AND user_id = ?");
$stmt->execute([$token, $_SESSION['user_id']]);
$upload = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$upload) jsonError('File not found or not yours.');

// Look up the recipient.
$stmt = $conn->prepare("SELECT id, username FROM users WHERE username = ?");
$stmt->execute([$username]);
$recipient = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$recipient) jsonError('User not found.');

// Prevent sharing with yourself.
if ((int) $recipient['id'] === (int) $_SESSION['user_id']) jsonError('Cannot share with yourself.');

// Insert the share record. The UNIQUE KEY (upload_id, shared_with) means a
// duplicate INSERT is silently ignored (ON DUPLICATE KEY UPDATE id=id).
$stmt = $conn->prepare(
    "INSERT INTO shared_files (upload_id, shared_by, shared_with)
     VALUES (?, ?, ?)
     ON DUPLICATE KEY UPDATE shared_at = shared_at"
);
$stmt->execute([$upload['id'], $_SESSION['user_id'], $recipient['id']]);

logEvent(
    $conn,
    'share',
    $_SESSION['user_id'],
    $_SESSION['username'],
    $upload['original_name'],
    "Shared with {$recipient['username']}"
);

jsonOk("File shared with {$recipient['username']}.");