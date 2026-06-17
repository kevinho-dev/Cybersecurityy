<?php
/**
 * verify.php — Password verification endpoint (returns JSON)
 */
require_once 'config.php';

header('Content-Type: application/json');

$token   = $_POST['token'] ?? '';
$password = $_POST['password'] ?? '';
$action  = $_POST['action'] ?? ''; // 'download' or 'share'

if (empty($token) || empty($password)) {
    echo json_encode(['success' => false, 'error' => 'Missing data.']);
    exit;
}

$stmt = $conn->prepare("SELECT password FROM uploads WHERE share_token = ?");
$stmt->execute([$token]);
$file = $stmt->fetch(PDO::FETCH_ASSOC);

if (!$file) {
    echo json_encode(['success' => false, 'error' => 'File not found.']);
    exit;
}

if (password_verify($password, $file['password'])) {
    // Unlock for this session
    $_SESSION['unlocked_tokens'][$token] = true;
    echo json_encode(['success' => true]);
} else {
    echo json_encode(['success' => false, 'error' => 'Wrong password.']);
}