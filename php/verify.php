<?php
require_once 'config.php';
header('Content-Type: application/json');

if (!isset($_SESSION['user_id'])) { echo json_encode(['success' => false, 'error' => 'Not authenticated.']); exit; }
if (!verifyCsrf()) { echo json_encode(['success' => false, 'error' => 'Invalid request.']); exit; }

 $token = $_POST['token'] ?? ''; $password = $_POST['password'] ?? ''; $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
if (!$token || !$password) { echo json_encode(['success' => false, 'error' => 'Missing data.']); exit; }
if (isRateLimited($conn, 'unlock_failed', $ip, 10, 10)) { echo json_encode(['success' => false, 'error' => 'Too many attempts. Try again later.']); exit; }

 $stmt = $conn->prepare("SELECT password FROM uploads WHERE share_token = ?"); $stmt->execute([$token]); $file = $stmt->fetch(PDO::FETCH_ASSOC);
if (!$file) { echo json_encode(['success' => false, 'error' => 'File not found.']); exit; }

if (password_verify($password, $file['password'])) {
    $_SESSION['unlocked_tokens'][$token] = true; echo json_encode(['success' => true]);
} else {
    logEvent($conn, 'unlock_failed', $_SESSION['user_id'], null, null, "Wrong password for token $token");
    echo json_encode(['success' => false, 'error' => 'Wrong password.']);
}