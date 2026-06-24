<?php
require_once 'config.php';
if (!isset($_SESSION['user_id'])) { http_response_code(403); exit; }
 $token = $_GET['token'] ?? ''; if (!preg_match('/^[a-f0-9]{64}$/', $token)) { http_response_code(400); exit; }

 $stmt = $conn->prepare("SELECT stored_name, mime_type FROM uploads WHERE share_token = ? AND user_id = ?"); $stmt->execute([$token, $_SESSION['user_id']]); $file = $stmt->fetch(PDO::FETCH_ASSOC);
if (!$file || !in_array($file['mime_type'], get_image_mimes())) { http_response_code(404); exit; }

 $path = __DIR__ . '/../uploads/' . $file['stored_name']; $real = realpath($path); $dir = realpath(__DIR__ . '/../uploads/');
if (!$real || strpos($real, $dir) !== 0 || !is_file($real)) { http_response_code(404); exit; }

header('Content-Type: ' . $file['mime_type']); header('Cache-Control: private, max-age=3600'); readfile($real);